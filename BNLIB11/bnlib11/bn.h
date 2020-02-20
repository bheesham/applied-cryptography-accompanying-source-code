/*
 * bn.h - the interface to the bignum routines.
 * All functions which return ints can potentially allocate memory
 * and return -1 if they are unable to. All "const" arguments
 * are unmodified.
 *
 * This is not particularly asymmetric, as some operations are of the
 * form a = b @ c, while others do a @= b.  In general, outputs may not
 * point to the same struct BigNums as inputs, except as specified
 * below.  This relationship is referred to as "being the same as".
 * This is not numerical equivalence.
 *
 * The "Q" operations take "unsigned" inputs.  Higher values of the
 * extra input may work on some implementations, but 65535 is the
 * highest portable value.  Just because UNSIGNED_MAX is larger than
 * that, or you know that the word size of the library is larger than that,
 * that, does *not* mean it's allowed.
 */
#ifndef BN_H
#define BN_H

struct BigNum {
	void *ptr;
	unsigned size;	/* Note: in (variable-sized) words */
	unsigned allocated;
};

/* Functions */

/*
 * You usually never have to call this function explicitly, as
 * bnBegin() takes care of it.  If the program jumps to address 0,
 * this function has bot been called.
 */
void bnInit(void);

/*
 * This initializes an empty struct BigNum to a zero value.
 * Do not use this on a BigNum which has had a value stored in it!
 */
void bnBegin(struct BigNum *bn);

/* Swap two BigNums.  Cheap. */
void bnSwap(struct BigNum *a, struct BigNum *b);

/* Reset an initialized bigNum to empty, pending deallocation. */
extern void (*bnEnd)(struct BigNum *bn);

/*
 * If you know you'll need space in the number soon, you can use this function
 * to ensure that there is room for at least "bits" bits.  Optional.
 * Returns <0 on out of memory, but the value is unaffected.
 */
extern int (*bnPrealloc)(struct BigNum *bn, unsigned bits);

/* Hopefully obvious.  dest = src.   dest may be the same as src. */
extern int (*bnCopy)(struct BigNum *dest, struct BigNum const *src);

/*
 * Mostly done automatically, but this removes leading zero words from
 * the internal representation of the BigNum.  Use is unclear.
 */
extern void (*bnNorm)(struct BigNum *bn);

/*
 * Move bytes between the given buffer and the given BigNum encoded in
 * base 256.  I.e. after either of these, the buffer will be equal to
 * (bn / 256^lsbyte) % 256^len.  The difference is which is altered to
 * match the other!
 */
extern void (*bnExtractBigBytes)(struct BigNum const *bn,
	unsigned char *dest, unsigned lsbyte, unsigned len);
extern int (*bnInsertBigBytes)(struct BigNum *bn, unsigned char const *src,
	unsigned lsbyte, unsigned len);

/* The same, but the buffer is little-endian. */
extern void (*bnExtractLittleBytes)(struct BigNum const *bn,
	unsigned char *dest, unsigned lsbyte, unsigned len);
extern int (*bnInsertLittleBytes)(struct BigNum *bn, unsigned char const *src,
	unsigned lsbyte, unsigned len);

/* Return the least-significant bits (at least 16) of the BigNum */
extern unsigned (*bnLSWord)(struct BigNum const *src);

/*
 * Return the number of significant bits in the BigNum.
 * 0 or 1+floor(log2(src))
 */
extern unsigned (*bnBits)(struct BigNum const *src);

/*
 * dest += src.  dest and src may be the same.  Guaranteed not to
 * allocate memory unnecessarily, so if you're sure bnBits(dest)
 * won't change, you don't need to check the return value.
 */
extern int (*bnAdd)(struct BigNum *dest, struct BigNum const *src);

/*
 * dest -= src.  dest and src may be the same, but bnSetQ(dest, 0) is faster.
 * if dest < src, returns +1 and sets dest = src-dest.
 */
extern int (*bnSub)(struct BigNum *dest, struct BigNum const *src);

/* Return sign (-1, 0, +1) of a-b.  a <=> b --> bnCmpQ(a, b) <=> 0 */
extern int (*bnCmpQ)(struct BigNum const *a, unsigned b);

/* dest = src, where 0 <= src < 2^16. */
extern int (*bnSetQ)(struct BigNum *dest, unsigned src);

/* dest += src, where 0 <= src < 2^16 */
extern int (*bnAddQ)(struct BigNum *dest, unsigned src);

/* dest -= src, where 0 <= src < 2^16 */
extern int (*bnSubQ)(struct BigNum *dest, unsigned src);

/* Return sign (-1, 0, +1) of a-b.  a <=> b --> bnCmp(a, b) <=> 0 */
extern int (*bnCmp)(struct BigNum const *a, struct BigNum const *b);

/* dest = src^2.  dest may be the same as src, but it costs time. */
extern int (*bnSquare)(struct BigNum *dest, struct BigNum const *src);

/* dest = a * b.  dest may be the same as a or b, but it costs time. */
extern int (*bnMul)(struct BigNum *dest, struct BigNum const *a,
	struct BigNum const *b);

/* dest = a * b, where 0 <= b < 2^16.  dest and a may be the same. */
extern int (*bnMulQ)(struct BigNum *dest, struct BigNum const *a, unsigned b);

/*
 * q = n/d, r = n%d.  r may be the same as n, but not d,
 * and q may not be the same as n or d.
 * re-entrancy issue: this temporarily modifies d, but restores
 * it for return.
 */
extern int (*bnDivMod)(struct BigNum *q, struct BigNum *r,
	struct BigNum const *n, struct BigNum const *d);
/*
 * dest = src % d.  dest and src may be the same, but not dest and d.
 * re-entrancy issue: this temporarily modifies d, but restores
 * it for return.
 */
extern int (*bnMod)(struct BigNum *dest, struct BigNum const *src,
	struct BigNum const *d);

/* return src % d, where 0 <= d < 2^16.  */
extern unsigned int (*bnModQ)(struct BigNum const *src, unsigned d);

/* n = n^exp, modulo "mod"   "mod" *must* be odd */
extern int (*bnExpMod)(struct BigNum *result, struct BigNum const *n,
	struct BigNum const *exp, struct BigNum const *mod);

/*
 * dest = n1^e1 * n2^e2, modulo "mod".  "mod" *must* be odd.
 * dest may be the same as n1 or n2.
 */
extern int (*bnDoubleExpMod)(struct BigNum *dest,
	struct BigNum const *n1, struct BigNum const *e1,
	struct BigNum const *n2, struct BigNum const *e2,
	struct BigNum const *mod);

/* n = 2^exp, modulo "mod"   "mod" *must* be odd */
extern int (*bnTwoExpMod)(struct BigNum *n, struct BigNum const *exp,
	struct BigNum const *mod);

/* dest = gcd(a, b).  The inputs may overlap arbitrarily. */
extern int (*bnGcd)(struct BigNum *dest, struct BigNum const *a,
	struct BigNum const *b);

/* dest = src^-1, modulo "mod".  dest may be the same as src. */
extern int (*bnInv)(struct BigNum *dest, struct BigNum const *src,
	struct BigNum const *mod);

/* Shift dest left "amt" places */
extern int (*bnLShift)(struct BigNum *dest, unsigned amt);
/* Shift dest right "amt" places, discarding low-order bits */
extern void (*bnRShift)(struct BigNum *dest, unsigned amt);

/* For the largest 2^k that divides n, divide n by it and return k. */
extern unsigned (*bnMakeOdd)(struct BigNum *n);

#endif/* !BN_H */
