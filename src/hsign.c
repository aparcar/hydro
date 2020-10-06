#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "base64.h"
#include "hydrogen.h"

#define CONTEXT "hsign"
#define COMMENTMAXBYTES 1024
#define COMMENT_PREFIX "untrusted comment: "
#define KEYNUMBYTES 8
#define SIGALG "Hy"

typedef struct SeckeyStruct_ {
    unsigned char sig_alg[2];
    unsigned char keynum[KEYNUMBYTES];
    unsigned char sk[hydro_sign_SECRETKEYBYTES];

} SeckeyStruct;

typedef struct PubkeyStruct_ {
    unsigned char sig_alg[2];
    unsigned char keynum[KEYNUMBYTES];
    unsigned char pk[hydro_sign_PUBLICKEYBYTES];
} PubkeyStruct;

typedef struct SigStruct_ {
    unsigned char sig_alg[2];
    unsigned char keynum[KEYNUMBYTES];
    unsigned char sig[hydro_sign_BYTES];
} SigStruct;

static int fput_b64(FILE* fp, const unsigned char* bin, size_t bin_len)
{
    const size_t b64_maxlen = (bin_len + 2) * 4 / 3 + 1;
    char* b64;
    b64 = malloc(b64_maxlen);
    bin_to_b64(b64, bin, b64_maxlen, bin_len);
    fprintf(fp, "%s\n", b64);
    free(b64);
}

void trim(char* str)
{
    size_t i = strlen(str);

    while (i-- > (size_t)0U) {
	if (str[i] == '\n' || str[i] == '\r') {
	    str[i] = 0;
	}
    }
}

static SigStruct* load_sig(const char* filename)
{
    char sig_comment[COMMENTMAXBYTES];
    SigStruct* sig_struct;
    FILE* fp;
    char* sig_s = NULL;
    size_t sig_s_size;
    size_t sig_struct_len;

    fp = fopen(filename, "r");
    fgets(sig_comment, (int)sizeof sig_comment, fp);
    sig_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *sig_struct) + 2U;
    sig_s = malloc(sig_s_size);
    fgets(sig_s, (int)sig_s_size, fp);
    fclose(fp);
    trim(sig_s);
    sig_struct = malloc(sizeof *sig_struct);
    b64_to_bin((unsigned char*)(void*)sig_struct, sig_s, sizeof *sig_struct, strlen(sig_s), &sig_struct_len);
    if (memcmp(sig_struct->sig_alg, SIGALG, sizeof sig_struct->sig_alg) != 0) {
	perror("Unsupported signature algorithm");
    }
    return sig_struct;
}

static PubkeyStruct* load_pubkey(const char* filename)
{
    char pk_comment[COMMENTMAXBYTES];
    PubkeyStruct* pubkey_struct;
    FILE* fp;
    char* pubkey_s = NULL;
    size_t pubkey_s_size;
    size_t pubkey_struct_len;

    fp = fopen(filename, "r");
    fgets(pk_comment, (int)sizeof pk_comment, fp);
    pubkey_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *pubkey_struct) + 2U;
    pubkey_s = malloc(pubkey_s_size);
    fgets(pubkey_s, (int)pubkey_s_size, fp);
    fclose(fp);
    trim(pubkey_s);
    pubkey_struct = malloc(sizeof *pubkey_struct);
    b64_to_bin((unsigned char*)(void*)pubkey_struct, pubkey_s, sizeof *pubkey_struct, strlen(pubkey_s), &pubkey_struct_len);
    if (memcmp(pubkey_struct->sig_alg, SIGALG, sizeof pubkey_struct->sig_alg) != 0) {
	perror("Unsupported signature algorithm");
    }
    return pubkey_struct;
}

static SeckeyStruct* load_seckey(const char* filename)
{
    char sk_comment[COMMENTMAXBYTES];
    SeckeyStruct* seckey_struct;
    FILE* fp;
    char* seckey_s = NULL;
    size_t seckey_s_size;
    size_t seckey_struct_len;

    fp = fopen(filename, "r");
    fgets(sk_comment, (int)sizeof sk_comment, fp);
    seckey_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *seckey_struct) + 2U;
    seckey_s = malloc(seckey_s_size);
    fgets(seckey_s, (int)seckey_s_size, fp);
    fclose(fp);
    trim(seckey_s);
    seckey_struct = malloc(sizeof *seckey_struct);
    b64_to_bin((unsigned char*)(void*)seckey_struct, seckey_s, sizeof *seckey_struct, strlen(seckey_s), &seckey_struct_len);
    if (memcmp(seckey_struct->sig_alg, SIGALG, sizeof seckey_struct->sig_alg) != 0) {
	perror("Unsupported signature algorithm");
    }
    return seckey_struct;
}

static unsigned char* message_load(size_t* message_len, const char* message_file)
{
    FILE* fp;
    unsigned char* message;
    fp = fopen(message_file, "rb");
    fseek(fp, 0L, SEEK_END);
    *message_len = ftell(fp);
    message = malloc((size_t)*message_len);
    rewind(fp);
    fread(message, *message_len, (size_t)1U, fp);
    puts("message load");

    return message;
}

static int sign(SeckeyStruct* seckey_struct, const char* message_file, const char* sig_file, const char* comment)
{
    SigStruct sig_struct;
    FILE* fp;
    unsigned char* message;
    size_t comment_lengt;
    size_t message_len;

    message = message_load(&message_len, message_file);
    puts("got message");
    memcpy(sig_struct.sig_alg, SIGALG, sizeof sig_struct.sig_alg);
    memcpy(sig_struct.keynum, seckey_struct->keynum, sizeof sig_struct.keynum);

    puts("signed");
    hydro_sign_create(sig_struct.sig, message, message_len, CONTEXT, seckey_struct->sk);

    puts("write sig");
    free(message);

    fp = fopen(sig_file, "w");
    fprintf(fp, "%s%s\n", COMMENT_PREFIX, comment);
    fput_b64(fp, (unsigned char*)(void*)&sig_struct, sizeof sig_struct);
    fclose(fp);
}

static int verify(PubkeyStruct* pubkey_struct, const char* message_file, const char* sig_file)
{
    unsigned char* message;
    size_t comment_lengt;
    size_t message_len;
    SigStruct* sig_struct;

    sig_struct = load_sig("hsign.sig");
    message = message_load(&message_len, message_file);

    if (hydro_sign_verify(sig_struct->sig, message, message_len, CONTEXT, pubkey_struct->pk) != 0) {
	puts("Good Signature");
	return 1;
    }
    puts("Bad Signature");
    return 0;
}

static int generate(const char* pk_file, const char* sk_file, const char* comment, int force)
{
    FILE* fp;
    hydro_sign_keypair key_pair;
    hydro_sign_keygen(&key_pair);

    // secret key
    SeckeyStruct* seckey_struct = malloc(sizeof(SeckeyStruct));
    memcpy(seckey_struct->sig_alg, SIGALG, sizeof seckey_struct->sig_alg);
    hydro_random_buf(seckey_struct->keynum, sizeof seckey_struct->keynum);
    fp = fopen(sk_file, "w");
    memcpy(seckey_struct->sk, key_pair.sk, hydro_sign_SECRETKEYBYTES);
    fprintf(fp, "%sprivate key %x %s\n", COMMENT_PREFIX, (char*)seckey_struct->keynum, comment);
    fput_b64(fp, (unsigned char*)(void*)seckey_struct, sizeof *seckey_struct);
    fclose(fp);

    // public key
    PubkeyStruct* pubkey_struct = malloc(sizeof(PubkeyStruct));
    memcpy(pubkey_struct->sig_alg, SIGALG, sizeof pubkey_struct->sig_alg);
    memcpy(pubkey_struct->keynum, seckey_struct->keynum, sizeof pubkey_struct->keynum);
    fp = fopen(pk_file, "w");
    fprintf(fp, "%spubblic key %x %s\n", COMMENT_PREFIX, (char*)pubkey_struct->keynum, comment);
    fput_b64(fp, (unsigned char*)(void*)pubkey_struct, sizeof *pubkey_struct);
    fclose(fp);
}

int main(int argc, char* argv[])
{
    PubkeyStruct* pubkey_struct;
    SeckeyStruct* seckey_struct;
    SigStruct* sig_struct;

    generate("key.pub", "key.sec", "no comment", 0);
    pubkey_struct = load_pubkey("key.pub");
    seckey_struct = load_seckey("key.sec");
    puts("sign");
    sign(seckey_struct, "./test.txt", "hsign.sig", "kein kommentar");
    verify(pubkey_struct, "./test.txt", "hsign.sig");
    printf("OK\n");
}
