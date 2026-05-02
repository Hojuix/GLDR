/*
 * GLDR Source Code
 * Hojuix (호주IX / 호주익스) 2026
 * License: MIT
 * NOTICE: I (THE AUTHOR) DO NOT ASSUME ANY LEGAL LIABILITY FOR THE USE OF THIS SOFTWARE.
 *         THE END-USER ASSUMES ALL LEGAL AND PERSONAL LIABILITY.
 *         THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL PURPOSES ONLY.
 */
 
// Notice: I am not too worried about error checking/handling and optimization here as this
//         is used to build GLDR. This is NOT actual bootloader code.

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * SECRETS START
 */

// Main AES Key (MAEK)
uint8_t MAEK[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Kernel AES IV (KAIV)
uint8_t KAIV[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

// Initrd AES IV (IAIV)
uint8_t IAIV[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

// Kernel Cmdline IV (CAIV)
uint8_t CAIV[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

char AES_AADB[] = "examplesentence";
const char COREBOOT_SERIAL[] = "0000000000";
const char* SODIMM_PART_NUMBER = "Example";
const char* SODIMM_SERIAL_NUMBER = "a0a1a2a3";
uint16_t SODIMM_ARRAY_HNDL = 0x0000;

/*
 * SECRETS END
 * CONSTANTS START
 */

// GLOB Headers
typedef struct {
    uint32_t signature;     // GLOB Section Signature
    uint32_t size;          // Size of section data in bytes
    uint32_t offset;        // Offset of actual section data in file
} __attribute__((packed)) GLOB_Section_t;

typedef struct {
    uint32_t signature;     // GLOB Signature
    uint8_t sectionCount;   // GLOB Section Count (Must be 4)
    GLOB_Section_t sections[10]; // GLOB Sections
} __attribute__((packed)) GLOB_Hdr_t;


// GLOB Signatures
#define GLOB_SIGNATURE                      0x474C4F42    // GLOB Signature
#define GLOB_SECTION_SIG_KERN               0x4B45524E    // GLOB Kernel Section
#define GLOB_SECTION_SIG_INRD               0x494E5244    // GLOB Initrd Section
#define GLOB_SECTION_SIG_CMDL               0x434D444C    // GLOB Cmdline Section
#define GLOB_SECTION_SIG_KSIG               0x4B534947    // GLOB Kernel RSA Signature Section
#define GLOB_SECTION_SIG_ISIG               0x49534947    // GLOB Initrd RSA Signature Section
#define GLOB_SECTION_SIG_CSIG               0x43534947    // GLOB Cmdline RSA Signature Section
#define GLOB_SECTION_SIG_KTAG               0x4B544147    // GLOB Kernel AES256GCM Tag Section
#define GLOB_SECTION_SIG_ITAG               0x49544147    // GLOB Initrd AES256GCM Tag Section
#define GLOB_SECTION_SIG_CTAG               0x43544147    // GLOB Cmdline AES256GCM Tag Section
#define GLOB_SECTION_SIG_RMOD               0x524D4F44    // GLOB Restriction Mode RSA Signature Section

// KGLDR Request Signatures
uint32_t KGLDR_Sig_MAEK = 0x4D41454B;    // Main AES Key Signature
uint32_t KGLDR_Sig_KAIV = 0x4B414956;    // Kernel AES IV Signature
uint32_t KGLDR_Sig_IAIV = 0x49414956;    // Initrd AES IV Signature
uint32_t KGLDR_Sig_CAIV = 0x43414956;    // Cmdline AES IV Signature
uint32_t KGLDR_Sig_RMOD = 0x524D4F44;    // Restriction Mode Signature
uint32_t KGLDR_Sig_CLLV = 0x434C4C56;    // Short for 'Cleanup and Leave'. Clean all keys from memory, disable functionality
uint32_t KGLDR_Sig_PNIC = 0x504E4943;    // Panic the kernel
uint32_t KGLDR_Sig_INIT = 0x494E4954;    // Run seutpEnvironment() in KGLDR
uint32_t KGLDR_Sig_AAAD = 0x41414144;    // AES256GCM AAD
uint32_t KGLDR_Sig_BPOL = 0x42504F4C;    // Boot Policy

// KGLDR Communication Structures
char KGLDR_failCheck_panicMsg[] = "Fault injection suspected. Panicking kernel.";
char KGLDR_general_allocateFail[] = "Could not allocate kernel buffer.";
char KGLDR_general_copyFromUserFail[] = "Copying from user memory failed.";
char KGLDR_general_copyToUserFail[] = "Copying to user memory failed.";

// KGLDR Boot Policies
#define GLOB_LOCKDOWN_SIG_PERMISSIVE        0xb2fba1b9  // GLOB can be booted in any mode
#define GLOB_LOCKDOWN_SIG_SEMIPERMISSIVE    0xecdc0b12
#define GLOB_LOCKDOWN_SIG_LOCKDOWN          0xb79d1c05  // GLOB can ONLY be booted in Lockdown mode

/*
 * CONSTANTS END
 */

uint32_t xor(uint32_t value, const char* key) {
    size_t key_len = strlen(key);
    if (key_len == 0) return value;
    
    uint32_t result = value;
    uint8_t* bytes = (uint8_t*)&result;
    
    for (int i = 0; i < 4; i++) {
        bytes[i] ^= key[i % key_len];
    }
    return result;
}

void xor_str(uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

int main() {
    // General signatures
    printf("// Request Signatures (XOR'd against SODIMM PN)\n");
    printf("#define XOR_SIG_MAEK 0x%.8x\t\t// Main AES Key\n", xor(KGLDR_Sig_MAEK, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_KAIV 0x%.8x\t\t// Kernel AES IV\n", xor(KGLDR_Sig_KAIV, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_IAIV 0x%.8x\t\t// Initrd AES IV\n", xor(KGLDR_Sig_IAIV, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_CAIV 0x%.8x\t\t// Cmdline AES IV\n", xor(KGLDR_Sig_CAIV, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_RMOD 0x%.8x\t\t// Restriction Mode. Returns Permissive/Lockdown mode\n", xor(KGLDR_Sig_RMOD, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_CLLV 0x%.8x\t\t// Short for 'Cleanup and Leave'. Clean all keys from memory, disable functionality\n", xor(KGLDR_Sig_CLLV, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_PNIC 0x%.8x\t\t// Panic the kernel\n", xor(KGLDR_Sig_PNIC, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_INIT 0x%.8x\t\t// Run setupEnvironment()\n", xor(KGLDR_Sig_INIT, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_AAAD 0x%.8x\t\t// AES-256-GCM AAD\n", xor(KGLDR_Sig_AAAD, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_BPOL 0x%.8x\t\t// Boot Policy\n", xor(KGLDR_Sig_BPOL, SODIMM_PART_NUMBER));
    printf("\n");

    // Boot Policy Settings
    uint32_t KGLDR_Sig_BPOL_PERM = 0xb2fba1b9;
    uint32_t KGLDR_Sig_BPOL_SEPM = 0xecdc0b12;
    uint32_t KGLDR_Sig_BPOL_LKDN = 0xb79d1c05;
    printf("// Boot Policy Settings\n");
    printf("#define XOR_SIG_BPOL_PERM 0x%.8x\t\t// Permissive Boot\n", xor(KGLDR_Sig_BPOL_PERM, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_BPOL_SEPM 0x%.8x\t\t// Semi-Permissive Boot\n", xor(KGLDR_Sig_BPOL_SEPM, SODIMM_PART_NUMBER));
    printf("#define XOR_SIG_BPOL_LKDN 0x%.8x\t\t// Lockdown Boot\n\n", xor(KGLDR_Sig_BPOL_LKDN, SODIMM_PART_NUMBER));

    printf("// AES encoded buffers (XOR'd against SODIMM PN)\n");
    // failCheck() Kernel Panic message
    int failCheck_panicMsg_len = strlen(KGLDR_failCheck_panicMsg);
    xor_str((uint8_t*)KGLDR_failCheck_panicMsg, failCheck_panicMsg_len, (const uint8_t*)SODIMM_PART_NUMBER, strlen(SODIMM_PART_NUMBER));
    printf("u8 GLDR_failCheck_panicMsg[%d] = {", failCheck_panicMsg_len);
    for (int i = 0; i < failCheck_panicMsg_len; i++) {
        if (i % 8 == 0) {
            printf("\n\t");
        }
        if (i == failCheck_panicMsg_len - 1) {
            printf("0x%.2x", KGLDR_failCheck_panicMsg[i]);
        } else {
            printf("0x%.2x, ", KGLDR_failCheck_panicMsg[i]);
        }
    }
    printf("\n};\n\n");

    // General Allocation Failure message
    int general_allocateFail_len = strlen(KGLDR_general_allocateFail);
    xor_str((uint8_t*)KGLDR_general_allocateFail, general_allocateFail_len, (const uint8_t*)SODIMM_PART_NUMBER, strlen(SODIMM_PART_NUMBER));
    printf("u8 GLDR_general_allocateFail[%d] = {", general_allocateFail_len);
    for (int i = 0; i < general_allocateFail_len; i++) {
        if (i % 8 == 0) {
            printf("\n\t");
        }
        if (i == general_allocateFail_len - 1) {
            printf("0x%.2x", KGLDR_general_allocateFail[i]);
        } else {
            printf("0x%.2x, ", KGLDR_general_allocateFail[i]);
        }
    }
    printf("\n};\n\n");

    // General CopyFromUser Failure message
    int general_copyFromUserFail_len = strlen(KGLDR_general_copyFromUserFail);
    xor_str((uint8_t*)KGLDR_general_copyFromUserFail, general_copyFromUserFail_len, (const uint8_t*)SODIMM_PART_NUMBER, strlen(SODIMM_PART_NUMBER));
    printf("u8 GLDR_general_copyFromUserFail[%d] = {", general_copyFromUserFail_len);
    for (int i = 0; i < general_copyFromUserFail_len; i++) {
        if (i % 8 == 0) {
            printf("\n\t");
        }
        if (i == general_copyFromUserFail_len - 1) {
            printf("0x%.2x", KGLDR_general_copyFromUserFail[i]);
        } else {
            printf("0x%.2x, ", KGLDR_general_copyFromUserFail[i]);
        }
    }
    printf("\n};\n\n");

    // General CopyToUser Failure message
    int general_copyToUserFail_len = strlen(KGLDR_general_copyToUserFail);
    xor_str((uint8_t*)KGLDR_general_copyToUserFail, general_copyToUserFail_len, (const uint8_t*)SODIMM_PART_NUMBER, strlen(SODIMM_PART_NUMBER));
    printf("u8 GLDR_general_copyToUserFail[%d] = {", general_copyToUserFail_len);
    for (int i = 0; i < general_copyToUserFail_len; i++) {
        if (i % 8 == 0) {
            printf("\n\t");
        }
        if (i == general_copyToUserFail_len - 1) {
            printf("0x%.2x", KGLDR_general_copyToUserFail[i]);
        } else {
            printf("0x%.2x, ", KGLDR_general_copyToUserFail[i]);
        }
    }
    printf("\n};\n\n");

    // Main AES Key
    int MAEK_len = sizeof(MAEK);
    xor_str((uint8_t*)MAEK, MAEK_len, (const uint8_t*)SODIMM_PART_NUMBER, strlen(SODIMM_PART_NUMBER));
    printf("u8 GLDR_MAEK[%d] = {", MAEK_len);
    for (int i = 0; i < MAEK_len; i++) {
        if (i % 8 == 0) {
            printf("\n\t");
        }
        if (i == MAEK_len - 1) {
            printf("0x%.2x", MAEK[i]);
        } else {
            printf("0x%.2x, ", MAEK[i]);
        }
    }
    printf("\n};\n\n");

    // Kernel AES IV
    int KAIV_len = sizeof(KAIV);
    xor_str((uint8_t*)KAIV, KAIV_len, (const uint8_t*)SODIMM_PART_NUMBER, strlen(SODIMM_PART_NUMBER));
    printf("u8 GLDR_KAIV[%d] = {", KAIV_len);
    for (int i = 0; i < KAIV_len; i++) {
        if (i % 8 == 0) {
            printf("\n\t");
        }
        if (i == KAIV_len - 1) {
            printf("0x%.2x", KAIV[i]);
        } else {
            printf("0x%.2x, ", KAIV[i]);
        }
    }
    printf("\n};\n\n");

    // Initrd AES IV
    int IAIV_len = sizeof(IAIV);
    xor_str((uint8_t*)IAIV, IAIV_len, (const uint8_t*)SODIMM_PART_NUMBER, strlen(SODIMM_PART_NUMBER));
    printf("u8 GLDR_IAIV[%d] = {", IAIV_len);
    for (int i = 0; i < IAIV_len; i++) {
        if (i % 8 == 0) {
            printf("\n\t");
        }
        if (i == IAIV_len - 1) {
            printf("0x%.2x", IAIV[i]);
        } else {
            printf("0x%.2x, ", IAIV[i]);
        }
    }
    printf("\n};\n\n");

    // Cmdline AES IV
    int CAIV_len = sizeof(CAIV);
    xor_str((uint8_t*)CAIV, CAIV_len, (const uint8_t*)SODIMM_PART_NUMBER, strlen(SODIMM_PART_NUMBER));
    printf("u8 GLDR_CAIV[%d] = {", CAIV_len);
    for (int i = 0; i < CAIV_len; i++) {
        if (i % 8 == 0) {
            printf("\n\t");
        }
        if (i == CAIV_len - 1) {
            printf("0x%.2x", CAIV[i]);
        } else {
            printf("0x%.2x, ", CAIV[i]);
        }
    }
    printf("\n};\n\n");

    // AES AAD
    int AAAD_len = strlen(AES_AADB);
    xor_str((uint8_t*)AES_AADB, AAAD_len, (const uint8_t*)SODIMM_PART_NUMBER, strlen(SODIMM_PART_NUMBER));
    printf("u8 GLDR_AAAD[%d] = {", AAAD_len);
    for (int i = 0; i < AAAD_len; i++) {
        if (i % 8 == 0) {
            printf("\n\t");
        }
        if (i == AAAD_len - 1) {
            printf("0x%.2x", AES_AADB[i]);
        } else {
            printf("0x%.2x, ", AES_AADB[i]);
        }
    }
    printf("\n};\n");

    return 0;
}
