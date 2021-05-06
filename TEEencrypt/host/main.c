/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#define _CRT_SECURE_NO_WARNINGS
#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char text[64] = {0,};
	char key[1] = {0,};
	int textlen=64;
	int keylen=1;
	FILE *fp;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	/* File Encrpyt */
	if (strcmp(argv[1], "-e") == 0) {
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						TEEC_MEMREF_TEMP_INOUT,
					 	TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = text;
		op.params[0].tmpref.size = textlen;
		op.params[1].tmpref.buffer = key;
		op.params[1].tmpref.size = keylen;
		
		/* Load File */
		printf("File reading : %s\n", argv[2]);
		fp = fopen(argv[2], "r");
		fread(text, 1, 64, fp);
		printf("data : %s\n", text);
		fclose(fp);
		key[0] = 'A';

		/* TA_TEEencrypt_CMD_ENCRYPT */
		memcpy(op.params[0].tmpref.buffer, text, textlen);
		memcpy(op.params[1].tmpref.buffer, key, keylen);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENCRYPT, &op,
				 	&err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		
		memcpy(text, op.params[0].tmpref.buffer, textlen);
		memcpy(key, op.params[1].tmpref.buffer, keylen);

		printf("Ciphertext : %s\n", text);
		printf("Cipherkey : %s\n", key);

		/* Save File */
		fp = fopen("/root/ciphertext.txt", "w");
		fputs(text, fp);
		fclose(fp);
		printf("Generate /root/ciphertext.txt\n");

		fp = fopen("/root/key.txt", "w");
		fputs(key, fp);
		fclose(fp);
		printf("Generate /root/key.txt\n");
	}
	
	/* File Decrpyt */
	if (strcmp(argv[1], "-d") == 0) {
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						TEEC_MEMREF_TEMP_INOUT,
					 	TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = text;
		op.params[0].tmpref.size = textlen;
		op.params[1].tmpref.buffer = key;
		op.params[1].tmpref.size = keylen;

		/* Load File */
		printf("File reading : %s\n", argv[2]);
		fp = fopen(argv[2], "r");
		fread(text, 1, 64, fp);
		printf("data : %s\n", text);
		fclose(fp);
		
		printf("File reading : %s\n", argv[3]);
		fp = fopen(argv[3], "r");
		fread(key, 1, 1, fp);
		printf("data : %s\n", key);
		fclose(fp);
		
		/* TA_TEEencrypt_CMD_DECRYPT */
		memcpy(op.params[0].tmpref.buffer, text, textlen);
		memcpy(op.params[1].tmpref.buffer, key, keylen);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DECRYPT, &op,
				 	&err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		
		memcpy(text, op.params[0].tmpref.buffer, textlen);

		printf("Plaintext : %s\n", text);

		/* Save File */
		fp = fopen("/root/plaintext.txt", "w");
		fputs(text, fp);
		fclose(fp);
		printf("Generate /root/plaintext.txt\n");

	}

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	/*
	printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_INC_VALUE, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("TA incremented value to %d\n", op.params[0].value.a);
	*/
	

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
