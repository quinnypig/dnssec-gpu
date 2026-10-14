// MIT-licensed experimental RSA/SHA-256 batch signer. See README security limits.
#include <cuda_runtime.h>
#include <stdint.h>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <atomic>
#include <omp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <gmp.h>
#include "cgbn/cgbn.h"
#include "powm.cuh"

using Params=powm_params_t<8,1024,5>;
using Pow=powm_odd_t<Params>;
using Instance=Pow::instance_t;

__global__ void exponentiate(Instance *items, int count, cgbn_error_report_t *report) {
    int id=(blockIdx.x*blockDim.x+threadIdx.x)/Params::TPI;
    if(id>=count) return;
    Pow engine(cgbn_report_monitor,report,id);
    Pow::bn_t x,d,p,result;
    cgbn_load(engine._env,x,&items[id].x);
    cgbn_load(engine._env,d,&items[id].power);
    cgbn_load(engine._env,p,&items[id].modulus);
    engine.fixed_window_powm_odd(result,x,d,p);
    cgbn_store(engine._env,&items[id].result,result);
}

struct Signer {
    EVP_PKEY *key=nullptr;
    BIGNUM *p=nullptr,*q=nullptr,*dp=nullptr,*dq=nullptr,*qi=nullptr;
    Instance *device=nullptr;
    cgbn_error_report_t *report=nullptr;
    size_t capacity=0;
    std::string error;
};
static bool cuda_ok(Signer *s,cudaError_t e) {
    if(e==cudaSuccess) return true;
    s->error=cudaGetErrorString(e); return false;
}
extern "C" const char *signer_error(void *ptr) {return static_cast<Signer*>(ptr)->error.c_str();}
extern "C" void signer_close(void *ptr) {
    auto *s=static_cast<Signer*>(ptr);if(!s)return;
    if(s->device) cudaFree(s->device);
    if(s->report)cgbn_error_report_free(s->report);
    EVP_PKEY_free(s->key);
    BN_clear_free(s->p);BN_clear_free(s->q);BN_clear_free(s->dp);BN_clear_free(s->dq);BN_clear_free(s->qi);
    delete s;
}
extern "C" void *signer_open(const char *pem) {
    auto *s=new Signer;
    BIO *bio=BIO_new_mem_buf(pem,-1);
    s->key=PEM_read_bio_PrivateKey(bio,nullptr,nullptr,nullptr);BIO_free(bio);
    if(!s->key || !EVP_PKEY_is_a(s->key,"RSA") || EVP_PKEY_get_bits(s->key)!=2048 ||
       !EVP_PKEY_get_bn_param(s->key,OSSL_PKEY_PARAM_RSA_FACTOR1,&s->p) ||
       !EVP_PKEY_get_bn_param(s->key,OSSL_PKEY_PARAM_RSA_FACTOR2,&s->q) ||
       !EVP_PKEY_get_bn_param(s->key,OSSL_PKEY_PARAM_RSA_EXPONENT1,&s->dp) ||
       !EVP_PKEY_get_bn_param(s->key,OSSL_PKEY_PARAM_RSA_EXPONENT2,&s->dq) ||
       !EVP_PKEY_get_bn_param(s->key,OSSL_PKEY_PARAM_RSA_COEFFICIENT1,&s->qi) ||
       BN_num_bits(s->p)!=1024 || BN_num_bits(s->q)!=1024) {signer_close(s);return nullptr;}
    return s;
}
extern "C" int signer_cpu(void *ptr,const unsigned char *digests,size_t count,unsigned char *out,int threads) {
    auto *s=static_cast<Signer*>(ptr);std::atomic<bool> failed(false);
    if(threads<1 || count==0)return -1;
    #pragma omp parallel num_threads(threads)
    {
        EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new(s->key,nullptr);
        bool ready=ctx && EVP_PKEY_sign_init(ctx)>0 &&
            EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PADDING)>0 &&
            EVP_PKEY_CTX_set_signature_md(ctx,EVP_sha256())>0;
        if(!ready)failed=true;
        #pragma omp for schedule(static)
        for(size_t i=0;i<count;i++) {
            size_t len=256;
            if(!ready || EVP_PKEY_sign(ctx,out+256*i,&len,digests+32*i,32)<=0 || len!=256)failed=true;
        }
        EVP_PKEY_CTX_free(ctx);
    }
    if(failed) {s->error="OpenSSL signing failed";return -1;}return 0;
}
extern "C" int signer_gpu(void *ptr,const unsigned char *digests,size_t count,unsigned char *out,int threads) {
    auto *s=static_cast<Signer*>(ptr);
    if(threads<1 || count==0 || count>1000000) {s->error="invalid batch size or threads";return -1;}
    std::vector<Instance> items(count*2);
    std::atomic<bool> failed(false);
    // PKCS#1 v1.5 SHA-256 DigestInfo, RFC 5702 algorithm 8.
    const unsigned char der[]={0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
    #pragma omp parallel num_threads(threads)
    {
        BN_CTX *ctx=BN_CTX_new(); BIGNUM *m=BN_new(), *r=BN_new();
        #pragma omp for schedule(static)
        for(size_t i=0;i<count;i++) {
            unsigned char em[256];memset(em,0xff,sizeof(em));em[0]=0;em[1]=1;em[204]=0;
            memcpy(em+205,der,sizeof(der));memcpy(em+224,digests+32*i,32);
            if(!BN_bin2bn(em,256,m)) {failed=true;continue;}
            for(int half=0;half<2;half++) {
                auto &item=items[2*i+half];const BIGNUM *prime=half?s->q:s->p,*power=half?s->dq:s->dp;
                if(!BN_mod(r,m,prime,ctx) || BN_bn2lebinpad(r,(unsigned char*)item.x._limbs,128)!=128 ||
                   BN_bn2lebinpad(prime,(unsigned char*)item.modulus._limbs,128)!=128 ||
                   BN_bn2lebinpad(power,(unsigned char*)item.power._limbs,128)!=128)failed=true;
            }
        }
        BN_clear_free(m);BN_clear_free(r);BN_CTX_free(ctx);
    }
    if(failed) {s->error="RSA input preparation failed";return -1;}
    if(!s->report && !cuda_ok(s,cgbn_error_report_alloc(&s->report)))return -1;
    if(s->capacity<count*2) {
        if(s->device && !cuda_ok(s,cudaFree(s->device)))return -1;
        s->device=nullptr;s->capacity=0;
        if(!cuda_ok(s,cudaMalloc(&s->device,items.size()*sizeof(Instance))))return -1;
        s->capacity=items.size();
    }
    cgbn_error_report_reset(s->report);
    if(!cuda_ok(s,cudaMemcpy(s->device,items.data(),items.size()*sizeof(Instance),cudaMemcpyHostToDevice)))return -1;
    exponentiate<<<(items.size()+15)/16,128>>>(s->device,items.size(),s->report);
    if(!cuda_ok(s,cudaGetLastError()) || !cuda_ok(s,cudaDeviceSynchronize()))return -1;
    if(cgbn_error_report_check(s->report)) {s->error=cgbn_error_string(s->report);return -1;}
    if(!cuda_ok(s,cudaMemcpy(items.data(),s->device,items.size()*sizeof(Instance),cudaMemcpyDeviceToHost)))return -1;
    #pragma omp parallel num_threads(threads)
    {
        BN_CTX *ctx=BN_CTX_new();BIGNUM *a=BN_new(),*b=BN_new(),*h=BN_new(),*sig=BN_new();
        #pragma omp for schedule(static)
        for(size_t i=0;i<count;i++) {
            BN_lebin2bn((unsigned char*)items[2*i].result._limbs,128,a);
            BN_lebin2bn((unsigned char*)items[2*i+1].result._limbs,128,b);
            if(!BN_mod_sub(h,a,b,s->p,ctx) || !BN_mod_mul(h,h,s->qi,s->p,ctx) ||
               !BN_mul(sig,h,s->q,ctx) || !BN_add(sig,sig,b) || BN_bn2binpad(sig,out+256*i,256)!=256)failed=true;
        }
        BN_clear_free(a);BN_clear_free(b);BN_clear_free(h);BN_clear_free(sig);BN_CTX_free(ctx);
    }
    OPENSSL_cleanse(items.data(),items.size()*sizeof(Instance));
    if(failed) {s->error="RSA CRT recombination failed";return -1;}return 0;
}
