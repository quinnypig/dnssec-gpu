/***

Copyright (c) 2018-2019, NVIDIA CORPORATION.  All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.

***/

// Adapted from NVIDIA CGBN sample_03_powm; only device exponentiation retained.
template<uint32_t tpi, uint32_t bits, uint32_t window_bits>
class powm_params_t {
  public:
  // parameters used by the CGBN context
  static const uint32_t TPB=0;                     // get TPB from blockDim.x  
  static const uint32_t MAX_ROTATION=4;            // good default value
  static const uint32_t SHM_LIMIT=0;               // no shared mem available
  static const bool     CONSTANT_TIME=false;       // constant time implementations aren't available yet
  
  // parameters used locally in the application
  static const uint32_t TPI=tpi;                   // threads per instance
  static const uint32_t BITS=bits;                 // instance size
  static const uint32_t WINDOW_BITS=window_bits;   // window size
};

template<class params>
class powm_odd_t {
  public:
  static const uint32_t window_bits=params::WINDOW_BITS;  // used a lot, give it an instance variable
  
  // define the instance structure
  typedef struct {
    cgbn_mem_t<params::BITS> x;
    cgbn_mem_t<params::BITS> power;
    cgbn_mem_t<params::BITS> modulus;
    cgbn_mem_t<params::BITS> result;
  } instance_t;

  typedef cgbn_context_t<params::TPI, params>   context_t;
  typedef cgbn_env_t<context_t, params::BITS>   env_t;
  typedef typename env_t::cgbn_t                bn_t;
  typedef typename env_t::cgbn_local_t          bn_local_t;

  context_t _context;
  env_t     _env;
  int32_t   _instance;
  
  __device__ __forceinline__ powm_odd_t(cgbn_monitor_t monitor, cgbn_error_report_t *report, int32_t instance) : _context(monitor, report, (uint32_t)instance), _env(_context), _instance(instance) {
  }

  __device__ __forceinline__ void fixed_window_powm_odd(bn_t &result, const bn_t &x, const bn_t &power, const bn_t &modulus) {
    bn_t       t;
    bn_local_t window[1<<window_bits];
    int32_t    index, position, offset;
    uint32_t   np0;

    // conmpute x^power mod modulus, using the fixed window algorithm
    // requires:  x<modulus,  modulus is odd

    // compute x^0 (in Montgomery space, this is just 2^BITS - modulus)
    cgbn_negate(_env, t, modulus);
    cgbn_store(_env, window+0, t);
    
    // convert x into Montgomery space, store into window table
    np0=cgbn_bn2mont(_env, result, x, modulus);
    cgbn_store(_env, window+1, result);
    cgbn_set(_env, t, result);
    
    // compute x^2, x^3, ... x^(2^window_bits-1), store into window table
    #pragma nounroll
    for(index=2;index<(1<<window_bits);index++) {
      cgbn_mont_mul(_env, result, result, t, modulus, np0);
      cgbn_store(_env, window+index, result);
    }

    // find leading high bit
    position=params::BITS - cgbn_clz(_env, power);

    // break the exponent into chunks, each window_bits in length
    // load the most significant non-zero exponent chunk
    offset=position % window_bits;
    if(offset==0)
      position=position-window_bits;
    else
      position=position-offset;
    index=cgbn_extract_bits_ui32(_env, power, position, window_bits);
    cgbn_load(_env, result, window+index);
    
    // process the remaining exponent chunks
    while(position>0) {
      // square the result window_bits times
      #pragma nounroll
      for(int sqr_count=0;sqr_count<window_bits;sqr_count++)
        cgbn_mont_sqr(_env, result, result, modulus, np0);
      
      // multiply by next exponent chunk
      position=position-window_bits;
      index=cgbn_extract_bits_ui32(_env, power, position, window_bits);
      cgbn_load(_env, t, window+index);
      cgbn_mont_mul(_env, result, result, t, modulus, np0);
    }
    
    // we've processed the exponent now, convert back to normal space
    cgbn_mont2bn(_env, result, result, modulus, np0);
  }
  
  __device__ __forceinline__ void sliding_window_powm_odd(bn_t &result, const bn_t &x, const bn_t &power, const bn_t &modulus) {
    bn_t         t, starts;
    int32_t      index, position, leading;
    uint32_t     mont_inv;
    bn_local_t   odd_powers[1<<window_bits-1];

    // conmpute x^power mod modulus, using Constant Length Non-Zero windows (CLNZ).
    // requires:  x<modulus,  modulus is odd
        
    // find the leading one in the power
    leading=params::BITS-1-cgbn_clz(_env, power);
    if(leading>=0) {
      // convert x into Montgomery space, store in the odd powers table
      mont_inv=cgbn_bn2mont(_env, result, x, modulus);
      
      // compute t=x^2 mod modulus
      cgbn_mont_sqr(_env, t, result, modulus, mont_inv);
      
      // compute odd powers window table: x^1, x^3, x^5, ...
      cgbn_store(_env, odd_powers, result);
      #pragma nounroll
      for(index=1;index<(1<<window_bits-1);index++) {
        cgbn_mont_mul(_env, result, result, t, modulus, mont_inv);
        cgbn_store(_env, odd_powers+index, result);
      }
  
      // starts contains an array of bits indicating the start of a window
      cgbn_set_ui32(_env, starts, 0);
  
      // organize p as a sequence of odd window indexes
      position=0;
      while(true) {
        if(cgbn_extract_bits_ui32(_env, power, position, 1)==0)
          position++;
        else {
          cgbn_insert_bits_ui32(_env, starts, starts, position, 1, 1);
          if(position+window_bits>leading)
            break;
          position=position+window_bits;
        }
      }
  
      // load first window.  Note, since the window index must be odd, we have to
      // divide it by two before indexing the window table.  Instead, we just don't
      // load the index LSB from power
      index=cgbn_extract_bits_ui32(_env, power, position+1, window_bits-1);
      cgbn_load(_env, result, odd_powers+index);
      position--;
      
      // Process remaining windows 
      while(position>=0) {
        cgbn_mont_sqr(_env, result, result, modulus, mont_inv);
        if(cgbn_extract_bits_ui32(_env, starts, position, 1)==1) {
          // found a window, load the index
          index=cgbn_extract_bits_ui32(_env, power, position+1, window_bits-1);
          cgbn_load(_env, t, odd_powers+index);
          cgbn_mont_mul(_env, result, result, t, modulus, mont_inv);
        }
        position--;
      }
      
      // convert result from Montgomery space
      cgbn_mont2bn(_env, result, result, modulus, mont_inv);
    }
    else {
      // p=0, thus x^p mod modulus=1
      cgbn_set_ui32(_env, result, 1);
    }
  }
  
};
