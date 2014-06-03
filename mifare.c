/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
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
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */
/**
 * @file mifare.c
 * @brief provide samples structs and functions to manipulate MIFARE Classic and Ultralight tags using libnfc
 */
#include "mifare.h"

#include <string.h>

#include <nfc/nfc.h>
#include "nfc-utils.h"

/**
 * @brief Execute a MIFARE Classic Command
 * @return Returns true if action was successfully performed; otherwise returns false.
 * @param pmp Some commands need additional information. This information should be supplied in the mifare_param union.
 *
 * The specified MIFARE command will be executed on the tag. There are different commands possible, they all require the destination block number.
 * @note There are three different types of information (Authenticate, Data and Value).
 *
 * First an authentication must take place using Key A or B. It requires a 48 bit Key (6 bytes) and the UID.
 * They are both used to initialize the internal cipher-state of the PN53X chip.
 * After a successful authentication it will be possible to execute other commands (e.g. Read/Write).
 * The MIFARE Classic Specification (http://www.nxp.com/acrobat/other/identification/M001053_MF1ICS50_rev5_3.pdf) explains more about this process.
 */

#include "crapto1.h"

#define SAK_FLAG_ATS_SUPPORTED 0x20
#define CASCADE_BIT 0x04
#define MAX_FRAME_LEN 264

static uint8_t abtRx[MAX_FRAME_LEN];
static uint8_t abtRxPar[MAX_FRAME_LEN];
static uint8_t abtUid[4];
struct Crypto1State *state;

bool    quiet_output = false;
bool    plain_output = false;

// ISO14443A Anti-Collision Commands
uint8_t  abtReqa[1] = { 0x26 };
uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtCommand[18] = { 0x00 };
uint8_t  abtCommandPar[18] = { 0x00 };
uint8_t  abtMessage[24] = {0x03, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
						   0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x49, 0x73,
						   0x6f, 0x44, 0x65, 0x70, 0x20, 0x30, 0x57, 0xdd};

static uint32_t
swap_endian32(const void* pui32)
{
  uint32_t ui32N = *((uint32_t*)pui32);
  return (((ui32N&0xFF)<<24)+((ui32N&0xFF00)<<8)+((ui32N&0xFF0000)>>8)+((ui32N&0xFF000000)>>24));
}

uint64_t swap_endian64(const void* pui64)
{
  uint64_t ui64N = *((uint64_t *)pui64);
  return (((ui64N&0xFF)<<56)+((ui64N&0xFF00)<<40)+((ui64N&0xFF0000)<<24)+((ui64N&0xFF000000)<<8)+((ui64N&0xFF00000000ull)>>8)+((ui64N&0xFF0000000000ull)>>24)+((ui64N&0xFF000000000000ull)>>40)+((ui64N&0xFF00000000000000ull)>>56));
}

static  bool
transmit_bits ( nfc_device *pnd, const uint8_t *pbtTx, const uint8_t *pbtTxPar, const size_t szTxBits)
{
	int szRxBits = -1;
  // Show transmitted command
  if (!quiet_output) {
    printf ("Sent bits:     ");
    print_hex_par (pbtTx, szTxBits, pbtTxPar);
  }
  szRxBits = nfc_initiator_transceive_bits (pnd, pbtTx, szTxBits, pbtTxPar, abtRx, sizeof(abtRx), abtRxPar);
  // Transmit the bit frame command, we don't use the arbitrary parity feature
  if ( szRxBits < 0)
    return false;

  // Show received answer
  if (!quiet_output) {
    printf ("Received bits: ");
    print_hex_par (abtRx, szRxBits, abtRxPar);
  }
  // Succesful transfer
  return true;
}


static  bool
transmit_bytes ( nfc_device *pnd, const uint8_t *pbtTx, const size_t szTx)
{
	int szRx = -1;
  // Show transmitted command
  if (!quiet_output) {
    printf ("Sent bits:     ");
    print_hex (pbtTx, szTx);
  }
  // Transmit the command bytes
  szRx = nfc_initiator_transceive_bytes (pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0);
  if ( szRx < 0) {
  	printf("not receive anything. \n");
    return false;
  }

  // Show received answer
  if (!quiet_output) {
    printf ("Received bits: ");
    print_hex (abtRx, szRx);
  }
  // Succesful transfer
  return true;
}

void decrypt_bit( struct Crypto1State* s, uint8_t* pbtRx, const size_t szRxBits, bool input, const uint8_t pbtIx )
{
   size_t i;
   uint8_t ks = 0;

   for( i = 0; i < szRxBits; i++ )
   {
     if( input ) ks |=  crypto1_bit( s, ( pbtIx >> i ) & 1, 1 ) << i;
	 else ks |= crypto1_bit( s, 0x00, 0) << i;
   }
   *pbtRx ^= ks;
}

bool decrypt( struct Crypto1State* s, uint8_t* pbtRx, uint8_t* pbtRxPar, const size_t szRxBytes, bool input, const uint8_t* pbtIx )
{
   size_t i;

   for( i = 0; i < szRxBytes; i++ )
   {
	 if( input ) decrypt_bit( s, &pbtRx[i], 8, true, pbtIx[i] );
	 else decrypt_bit( s, &pbtRx[i], 8, false, 0 );
	 pbtRxPar[ i ] ^= filter( s -> odd );
	 if( oddparity( pbtRx[ i ] ) != pbtRxPar[ i ] )
	   return false;
   }

   return true;
}

void encrypt( struct Crypto1State* s, uint8_t* pbtTx, uint8_t* pbtTxPar, const size_t szTxBytes, bool input )
{
   uint8_t ks;
   size_t i;

   for( i = 0; i < szTxBytes; i++ )
   {
     if( input ) ks =  crypto1_byte( s, pbtTx[ i ], 0 );
	 else ks = crypto1_byte( s, 0x00, 0);
	 pbtTxPar[ i ] = oddparity( pbtTx[ i ] ) ^ filter( s -> odd );
	 pbtTx[ i ] = pbtTx[ i ] ^ ks;
   }
}

int select_target(nfc_device *pnd, nfc_target *pnt) {
	  // Send the 7 bits request command specified in ISO 14443A (0x26)
	  if (!transmit_bits ( pnd, abtReqa, NULL, 7)) {
	    printf ("Error: No tag available\n");
	    return -1;
	  }
	  memcpy (pnt->nti.nai.abtAtqa, abtRx, 2);

	  // Anti-collision
	  transmit_bytes ( pnd, abtSelectAll, 2);

	  // Check answer
	  if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
	    printf("WARNING: BCC check failed!\n");
	    return -1;
	  }

	  // Save the UID CL1
	  memcpy (pnt->nti.nai.abtUid, abtRx, 4);
	  pnt->nti.nai.szUidLen = 4;

	  //Prepare and send CL1 Select-Command
	  memcpy (abtSelectTag + 2, abtRx, 5);
	  iso14443a_crc_append (abtSelectTag, 7);
	  transmit_bytes ( pnd, abtSelectTag, 9);
	  pnt->nti.nai.btSak = abtRx[0];

	return 1;
}

int select_application(nfc_device *pnd, nfc_target *pnt) {
	// abtCommand[0] = 0x00;
	// abtCommand[1] = 0xa4;
	// abtCommand[2] = 0x04;
	// abtCommand[3] = 0x00;
	// abtCommand[4] = 0x07;
	// abtCommand[5] = 0xf0;
	// abtCommand[6] = 0x01;
	// abtCommand[7] = 0x02;
	// abtCommand[8] = 0x03;
	// abtCommand[9] = 0x04;
	// abtCommand[10] = 0x05;
	// abtCommand[11] = 0x06;
	// abtCommand[12] = 0x00;
	// abtCommand[13] = 0xd8;
	// abtCommand[14] = 0xa1;

	abtCommand[0] = 0xe0;
	abtCommand[1] = 0x80;
	abtCommand[2] = 0x31;
	abtCommand[3] = 0x73;

	transmit_bytes(pnd, abtCommand, 4);

	abtCommand[0] = 0x02;
	abtCommand[1] = 0x00;
	abtCommand[2] = 0xa4;
	abtCommand[3] = 0x04;
	abtCommand[4] = 0x00;
	abtCommand[5] = 0x07;
	abtCommand[6] = 0xf0;
	abtCommand[7] = 0x01;
	abtCommand[8] = 0x02;
	abtCommand[9] = 0x03;
	abtCommand[10] = 0x04;
	abtCommand[11] = 0x05;
	abtCommand[12] = 0x06;
	abtCommand[13] = 0x00;
	abtCommand[14] = 0xd8;
	abtCommand[15] = 0xa1;

	transmit_bytes(pnd, abtCommand, 16);

	transmit_bytes(pnd, abtMessage, 24);

	return 1;
}

bool authentication( nfc_device *pnd, struct Crypto1State* s, uint8_t keyType, uint8_t blkNo, uint64_t key, bool nested ) {

	uint32_t nt, ar;
	int i;

	abtCommand[0] = keyType;
	abtCommand[1] = blkNo;
	iso14443a_crc_append (abtCommand, 2);

	if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
	    nfc_perror(pnd, "nfc_device_set_property_bool");
	    return false;
	  }

	if( nested ) { //If we are doing authentication after an authenticated session
		if( plain_output ) {
			printf( "Send Plain Text:" );
			print_hex( abtCommand, 4 );
		}
		encrypt( state, abtCommand, abtCommandPar, 4, false );
		if( !transmit_bits( pnd, abtCommand, abtCommandPar, 32 ) ) return false;
		memcpy( abtCommand, abtRx, 4 );
		for( i = 0; i < 4; i++ )
			abtCommand[ i ] ^= abtUid[ i ];
	}
	else
		if( !transmit_bytes ( pnd, abtCommand, 4) ) return false;

	state = crypto1_create( key );
	if( nested ) { //If we are doing authentication after an authenticated session
		if( !decrypt( state, abtRx, abtRxPar, 4, true, abtCommand ) )
			return false;
		if( plain_output ) {
			printf( "Received Plain Text:" );
			print_hex( abtRx, 4 );
		}
	}
	else {
		for( i = 0; i < 4; i++ )
			crypto1_byte( state, abtRx[i] ^ abtUid[i], 0 );
	}
	nt = swap_endian32( abtRx );

	abtCommand[0] = abtCommand[1] = abtCommand[2] = abtCommand[3] = 0x00;
	if( plain_output ) {
		printf( "Send Plain Text:" );
		print_hex( abtCommand, 4 );
	}
	encrypt( state, abtCommand, abtCommandPar, 4, true );

	// Configure the PARITY
	if (nfc_device_set_property_bool (pnd, NP_HANDLE_PARITY, false) < 0) {
		nfc_perror (pnd, "nfc_device_set_property_bool");
		return false;
	}

	ar = prng_successor( nt, 32 );
	for( i = 4; i < 8; i++ ) {
		ar = prng_successor( ar, 8 );
		abtCommand[i] = ar & 0xff;
	}
	if( plain_output ) {
		printf( "Send Plain Text:" );
		print_hex( &abtCommand[4], 4 );
	}
	encrypt( state, &abtCommand[4], &abtCommandPar[4], 4, false );

	if( !transmit_bits( pnd, abtCommand, abtCommandPar, 64 ) || !decrypt( state, abtRx, abtRxPar, 4, false, NULL )
		|| swap_endian32( abtRx ) != prng_successor( nt, 96 ) ) {
		printf( "\nWrong Tag Answer.\nAuthentication Failed.\n" );
		return false;
	}
	if( plain_output ) {
		printf( "Received Plain Text:" );
		print_hex( abtRx, 4 );
	}

	return true;
}

bool readBlock( nfc_device *pnd, struct Crypto1State* s, uint8_t * block, uint8_t blkNo ) {

	abtCommand[0] = MC_READ;
	abtCommand[1] = blkNo;
	iso14443a_crc_append (abtCommand, 2);
	if( plain_output ) {
		printf( "Send Plain Text:" );
		print_hex( abtCommand, 4 );
	}
	encrypt( state, abtCommand, abtCommandPar, 4, false );
	if( !transmit_bits( pnd, abtCommand, abtCommandPar, 32 ) || !decrypt( state, abtRx, abtRxPar, 18, false, NULL )) {
	  printf( "\nCommunication Failed.\n" );
	  return false;
	}
	if( plain_output ) {
		printf( "Received Plain Text:" );
		print_hex( abtRx, 18 );
	}
	memcpy( block, abtRx, 16 );
	return true;
}

static  bool
is_trailer_block(uint32_t uiBlock)
{
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock + 1) % 4 == 0);
  else
    return ((uiBlock + 1) % 16 == 0);
}

bool
nfc_initiator_mifare_cmd(nfc_device *pnd, const mifare_cmd mc, const uint8_t ui8Block, mifare_param *pmp)
{
//  uint8_t  abtRx[265];
//  size_t  szParamLen;
//  uint8_t  abtCmd[265];
  uint8_t abtKey[8] = { 0x00 };
  //bool    bEasyFraming;

//  abtCmd[0] = mc;               // The MIFARE Classic command
//  abtCmd[1] = ui8Block;         // The block address (1K=0x00..0x39, 4K=0x00..0xff)

  switch (mc) {
      // Read and store command have no parameter
    case MC_READ:
    case MC_STORE:
//      szParamLen = 0;
      return readBlock( pnd, state, pmp->mpd.abtData, ui8Block );
      break;

      // Authenticate command
    case MC_AUTH_A:
    case MC_AUTH_B:
//      szParamLen = sizeof(struct mifare_param_auth);
      memcpy(abtUid, pmp->mpa.abtAuthUid, 4 );
      memcpy(abtKey + 2, pmp->mpa.abtKey, 6 );
      return authentication( pnd, state, mc, ui8Block, swap_endian64(abtKey), state != NULL && is_trailer_block(ui8Block) );
      break;

      // Data command
    case MC_WRITE:
//      szParamLen = sizeof(struct mifare_param_data);
      break;

      // Value command
    case MC_DECREMENT:
    case MC_INCREMENT:
    case MC_TRANSFER:
//      szParamLen = sizeof(struct mifare_param_value);
      break;

      // Please fix your code, you never should reach this statement
    default:
      return false;
      break;
  }

  return false;
}

