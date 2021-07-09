#ifndef RSA_H
#define RSA_H

#include <stdio.h>

class RSA{
public:
    typedef unsigned long long ULL;
    typedef unsigned int UI;

	RSA();
	~RSA(){};
	void print_key() {
        printf("RSA keys: ");
        printf("p=%llu, q=%llu, phi=%llu, e=%llu, d=%llu", p,q,phi,e,d);
        printf("\n");
    }
	void get_public_key(ULL &_e, ULL &_n) {_e=e,_n=n;}
	void get_private_key(ULL &_d, ULL &_p, ULL &_q) {_p=p,_q=q,_d=d;}

	static void cipher(ULL *in, size_t len, ULL *out, ULL _e, ULL _n);
	static void decipher(const ULL *in, size_t len, ULL *out, ULL _d, ULL _p, ULL _q);
private:
	ULL p,q,phi,e,d,n;
	ULL ran();
	bool is_prime(ULL n,int t);
	int enum_prime_less_than(int n, UI *p);
	void generate_two_big_primes(ULL &a, ULL &b);
	ULL exgcd(ULL a, ULL b, ULL& x, ULL& y);

	static ULL mod_pro(ULL x,ULL y,ULL n);
	static ULL mod(ULL a,ULL b,ULL c);

};

#endif
