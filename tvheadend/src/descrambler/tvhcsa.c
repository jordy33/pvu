/*
 *  tvheadend - CSA wrapper
 *  Copyright (C) 2013 Adam Sutton
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "tvhcsa.h"
#include "input.h"
#include "input/mpegts/tsdemux.h"

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

static void
tvhcsa_aes_flush
  ( tvhcsa_t *csa, struct mpegts_service *s )
{
  /* empty - no queue */
}

static void
tvhcsa_aes_descramble
  ( tvhcsa_t *csa, struct mpegts_service *s, const uint8_t *tsb, int len )
{
  const uint8_t *tsb2, *end2;

  for (tsb2 = tsb, end2 = tsb + len; tsb2 < end2; tsb2 += 188)
    aes_decrypt_packet(csa->csa_aes_keys, (unsigned char *)tsb2);
  ts_recv_packet2(s, tsb, len);
}

static void
tvhcsa_csa_flush
  ( tvhcsa_t *csa, struct mpegts_service *s )
{
#if ENABLE_DVBCSA

  if(csa->csa_fill_even) {
    csa->csa_tsbbatch_even[csa->csa_fill_even].data = NULL;
    dvbcsa_bs_decrypt(csa->csa_key_even, csa->csa_tsbbatch_even, 184);
    csa->csa_fill_even = 0;
  }
  if(csa->csa_fill_odd) {
    csa->csa_tsbbatch_odd[csa->csa_fill_odd].data = NULL;
    dvbcsa_bs_decrypt(csa->csa_key_odd, csa->csa_tsbbatch_odd, 184);
    csa->csa_fill_odd = 0;
  }

  ts_recv_packet2(s, csa->csa_tsbcluster, csa->csa_fill * 188);

  csa->csa_fill = 0;

#else

  int r, l;
  unsigned char *vec[3];

  vec[0] = csa->csa_tsbcluster;
  vec[1] = csa->csa_tsbcluster + csa->csa_fill * 188;
  vec[2] = NULL;

  r = decrypt_packets(csa->csa_keys[0], vec);
  if(r > 0) {
    ts_recv_packet2(s, csa->csa_tsbcluster, r * 188);

    l = csa->csa_fill - r;
    assert(l >= 0);

    if(l > 0)
      memmove(csa->csa_tsbcluster, csa->csa_tsbcluster + r * 188, l * 188);
    csa->csa_fill = l;
  } else {
    csa->csa_fill = 0;
  }

#endif
}

static void
tvhcsa_csa_flush_extended_cw
  ( tvhcsa_t *csa, struct mpegts_service *s )
{
#if ENABLE_DVBCSA

  if(csa->csa_fill_even) {
    csa->csa_tsbbatch_even[csa->csa_fill_even].data = NULL;
    //dvbcsa_bs_decrypt(csa->csa_key_even, csa->csa_tsbbatch_even, 184);
    csa->csa_fill_even = 0;
  }
  if(csa->csa_fill_odd) {
    csa->csa_tsbbatch_odd[csa->csa_fill_odd].data = NULL;
    //dvbcsa_bs_decrypt(csa->csa_key_odd, csa->csa_tsbbatch_odd, 184);
    csa->csa_fill_odd = 0;
  }

  ts_recv_packet2(s, csa->csa_tsbcluster, csa->csa_fill * 188);

  csa->csa_fill = 0;

#else
  int r, i, j, k;
  uint32_t tsheader, tsheader2;
  uint16_t pid, pid2;
  uint8_t scramblingControl, oddeven;
  uint8_t *packetClusterV[256];
  uint8_t *packetClusterA[MAX_KEYS][64];  //separate cluster arrays for video and each audio track
  void *csakeyV = 0;
  void *csakeyA = {0};
  uint32_t scrambled_packets = 0;
  uint32_t scrambled_packetsA[MAX_KEYS] = {0};
  uint32_t cs = 0;  //video cluster start
  uint32_t ce = 1;  //video cluster end
  uint32_t cs_a[MAX_KEYS] = {0};  //cluster index for audio tracks

  packetClusterV[0] = NULL;
  j = 0;

  for (i = 0; i < csa->csa_fill * 188; i += 188) {

    tsheader = ((csa->csa_tsbcluster[i] <<24) | (csa->csa_tsbcluster[i+1] <<16)| (csa->csa_tsbcluster[i+2] <<8) | csa->csa_tsbcluster[i+3]) & 0xffffffff;
    pid = (tsheader & 0x1fff00) >> 8;
    scramblingControl = tsheader & 0xc0;
    oddeven = scramblingControl;

    if (scramblingControl == 0) continue;

      if ( pid == csa->csa_pids[csa->csa_vpid_index] ) {
        csakeyV = csa->csa_keys[csa->csa_vpid_index];
        cs = 0;
        ce = 1;
        packetClusterV[cs] = csa->csa_tsbcluster +i;  // set first cluster start;
        packetClusterV[ce] = csa->csa_tsbcluster +i + 188 -1;  // set first cluster start;
        scrambled_packets = 1;

        for (j = i + 188; j  < csa->csa_fill * 188; j += 188) {
          tsheader2 = ((csa->csa_tsbcluster[j] <<24) | (csa->csa_tsbcluster[j+1] <<16)| (csa->csa_tsbcluster[j+2] <<8) | csa->csa_tsbcluster[j+3]) & 0xffffffff;
          pid2 = (tsheader2 & 0x1fff00) >> 8;
          scramblingControl = tsheader2 & 0xc0;
          if (pid2 == pid) {
            if ( oddeven != scramblingControl ) {  // changed key so stop adding clusters
              break;
            }

            if (cs > ce) { //  First video packet for next cluster
              packetClusterV[cs] = csa->csa_tsbcluster +j;
              ce = cs +1;
            }
            scrambled_packets++;

          } else {
            if(cs < ce) { // First non-video packet - need to set end of video cluster
              packetClusterV[ce] = csa->csa_tsbcluster +j -1;
              cs = ce +1;
            }
// tvhdebug(LS_CSA, " pid =  %04x  %d   pid2 =  %04x  %d", pid,pid,pid2,pid2);

            if (scramblingControl == 0) continue;
            if (scramblingControl != oddeven) break;

            for (k = 0; k < MAX_KEYS; k++) {
// tvhdebug(LS_CSA, " pid =  %04x  %d   pid2 =  %04x  %d    k = %d pidk = %04x %d", pid,pid,pid2,pid2,k,csa->csa_pids[k],csa->csa_pids[k]);
              if (k  == csa->csa_vpid_index)
                continue;
              if (pid2 == csa->csa_pids[k]) {
                packetClusterA[k][cs_a[k]] = csa->csa_tsbcluster +j;
                cs_a[k]++;
                packetClusterA[k][cs_a[k]] = csa->csa_tsbcluster +j +188 -1;
                cs_a[k]++;
                scrambled_packetsA[k]++;
              }
            }
          }
        }

        if( cs > ce ) {  // last packet was not a video packet, so set null for end of all clusters
          packetClusterV[cs] = NULL;
        } else {
          if(scrambled_packets > 1) {  // last packet was a video packet, so set end of cluster to end of last packet
            packetClusterV[ce] = csa->csa_tsbcluster +j -1;
          }
          packetClusterV[ce+1] = NULL;  // add null to end of cluster list
        }

	r = csa->csa_cluster_parallelism;
        while( r >= csa->csa_cluster_parallelism) {
          r = decrypt_packets(csakeyV, packetClusterV);
          tvhdebug(LS_CSA, " decrypt r    i = %d  j = %d  r = %d  k = %d  ",i,j,r,k);
        }

        for(k = 0; k < MAX_KEYS; k++) {
          if (k  == csa->csa_vpid_index)
            continue;
          if(scrambled_packetsA[k]) {  // if audio track has scrambled packets, set null to mark end and decrypt
            packetClusterA[k][cs_a[k]] = NULL;
            csakeyA = csa->csa_keys[k];
            r = decrypt_packets(csakeyA, packetClusterA[k]);
       tvhdebug(LS_CSA, " decrypt audio r    i = %d  j = %d  r = %d  k = %d  ",i,j,r,k);
            cs_a[k] = 0;
            scrambled_packetsA[k] = 0;
          }
        }
      } else { // packet not video - decrypt single audio packet and continue
        for(k = 0; k < MAX_KEYS; k++) {
          if (k  == csa->csa_vpid_index)
            continue;
          if(pid == csa->csa_pids[k]) {
            csakeyA = csa->csa_keys[k];
          }
        }
        if(csakeyA != NULL) {
          packetClusterA[0][0] = csa->csa_tsbcluster +i;
          packetClusterA[0][1] = csa->csa_tsbcluster +i +188 -1;
          packetClusterA[0][2] = NULL;
          decrypt_packets(csakeyA, packetClusterA[0]);
        }
      }
      if (  j  >= csa->csa_fill * 188 ) {
       tvhdebug(LS_CSA, " FULL CSA_FILL !!!!!    i = %d  j = %d  r = %d  k = %d  ",i,j,j-i,k);
        break;
      } else if ( j > 0 ) {
        i = j - 188;
      }

      tvhdebug(LS_CSA, "  i = %d  j = %d  r = %d  k = %d  ",i,j,j-i,k);
  }

  ts_recv_packet2(s, csa->csa_tsbcluster,  csa->csa_fill * 188);

#endif
  csa->csa_fill = 0;

}

static void
tvhcsa_csa_descramble
  ( tvhcsa_t *csa, struct mpegts_service *s, const uint8_t *tsb, int tsb_len )
{
  const uint8_t *tsb_end = tsb + tsb_len;

  assert(csa->csa_fill >= 0 && csa->csa_fill < csa->csa_cluster_size);

#if ENABLE_DVBCSA
  uint8_t *pkt;
  int xc0;
  int ev_od;
  int len;
  int offset;
  int n;

  for ( ; tsb < tsb_end; tsb += 188) {

   pkt = csa->csa_tsbcluster + csa->csa_fill * 188;
   memcpy(pkt, tsb, 188);
   csa->csa_fill++;

   do { // handle this packet
     xc0 = pkt[3] & 0xc0;
     if(xc0 == 0x00) { // clear
       break;
     }
     if(xc0 == 0x40) { // reserved
       break;
     }
     if(xc0 == 0x80 || xc0 == 0xc0) { // encrypted
       ev_od = (xc0 & 0x40) >> 6; // 0 even, 1 odd
       pkt[3] &= 0x3f;  // consider it decrypted now
       if(pkt[3] & 0x20) { // incomplete packet
         offset = 4 + pkt[4] + 1;
         len = 188 - offset;
         n = len >> 3;
         // FIXME: //residue = len - (n << 3);
         if(n == 0) { // decrypted==encrypted!
           break; // this doesn't need more processing
         }
       } else {
         len = 184;
         offset = 4;
         // FIXME: //n = 23;
         // FIXME: //residue = 0;
       }
       if(ev_od == 0) {
         csa->csa_tsbbatch_even[csa->csa_fill_even].data = pkt + offset;
         csa->csa_tsbbatch_even[csa->csa_fill_even].len = len;
         csa->csa_fill_even++;
       } else {
         csa->csa_tsbbatch_odd[csa->csa_fill_odd].data = pkt + offset;
         csa->csa_tsbbatch_odd[csa->csa_fill_odd].len = len;
         csa->csa_fill_odd++;
       }
     }
   } while(0);

   if(csa->csa_fill == csa->csa_cluster_size) {
      if ( csa->use_extended_cw ) {
        tvhcsa_csa_flush_extended_cw(csa, s);
      }
      else {
        tvhcsa_csa_flush(csa, s);
      }
    }
  }

#else

  for ( ; tsb < tsb_end; tsb += 188 ) {

    memcpy(csa->csa_tsbcluster + csa->csa_fill * 188, tsb, 188);
    csa->csa_fill++;

    if(csa->csa_fill == csa->csa_cluster_size) {
      if ( csa->use_extended_cw ) {
        tvhcsa_csa_flush_extended_cw(csa, s);
      }
      else {
        tvhcsa_csa_flush(csa, s);
      }
    }

  }

#endif
}

static void
tvhcsa_des_flush
  ( tvhcsa_t *csa, struct mpegts_service *s )
{
  /* empty - no queue */
}

static void
tvhcsa_des_descramble
  ( tvhcsa_t *csa, struct mpegts_service *s, const uint8_t *tsb, int tsb_len )
{

  const uint8_t *tsb2, *end2;

  int j, k;
  uint32_t tsheader;
  uint16_t pid, offset;
  uint8_t scramblingControl, oddeven;
  uint8_t *pdata;

 // tvhdebug(LS_CSA, " tsb_len =  %d len/188 = %d", tsb_len, tsb_len/188);  

  tsheader = ( (*tsb) <<24 | *(tsb+1) <<16| *(tsb+2) <<8 | *(tsb+3)) & 0xffffffff;
  pid = (tsheader & 0x1fff00) >> 8;
  scramblingControl = tsheader & 0xc0;
  //    tvhwarn(LS_CSA, "pid 0x%4X scramb = 0x%X", pid, scramblingControl);  

  if (scramblingControl) { 

    if (scramblingControl == 0x80) {
      oddeven = 0;
    } else {
      oddeven = 1;
    }
//      tvhwarn(LS_CSA, "pid 0x%4X scramb = 0x%X  oddeven = %d ", pid, scramblingControl,oddeven);  

    for (j = 0; j < MAX_KEYS; j++) {
      if ( pid == csa->csa_pids[j] ) {

        for (tsb2 = tsb, end2 = tsb + tsb_len; tsb2 < end2; tsb2 += 188) {

//  tsheader = ( (*tsb2) <<24 | *(tsb2+1) <<16| *(tsb2+2) <<8 | *(tsb2+3)) & 0xffffffff;
//    if(tsheader & 0x20)
    if(*(tsb2+3) & 0x20)
      { offset = 4 + *(tsb2+4) + 1; //}
      }//tvhwarn(LS_CSA, "pid 0x%04X scramb = 0x%0X tsheader = 0x%08X  offset = %d 5 = 0x%X (%d)", pid, scramblingControl,tsheader,offset,*(tsb2+4),*(tsb2+4));  }
    else
      offset = 4; 
          for(k = offset; k + 7 < 188; k += 8) {

   	    pdata = (uint8_t *)(tsb2 +k);
            des2(pdata, csa->csa_des_keys[j][oddeven],0);
          }  

        *(uint8_t *)(tsb2+3) &= 0x3F;
        }
      break;
      }
    }
    if (j == MAX_KEYS )
      tvhwarn(LS_CSA, "No key for pid 0x%4X", pid);  

 }

  ts_recv_packet2(s, tsb, tsb_len);
}

int
tvhcsa_set_type( tvhcsa_t *csa, int type )
{
  if (csa->csa_type == type)
    return 0;
//  if (csa->csa_descramble)
//    return -1;
  switch (type) {
  case DESCRAMBLER_CSA:
   tvhtrace(LS_CSA, " Encryption CSA used !!! ");
    csa->csa_descramble = tvhcsa_csa_descramble;
    if (csa->use_extended_cw) {
      csa->csa_flush      = tvhcsa_csa_flush_extended_cw;
    } else {
      csa->csa_flush      = tvhcsa_csa_flush;
    }
    csa->csa_keylen     = 8;
    break;
  case DESCRAMBLER_DES:
   tvhtrace(LS_CSA, " Encryption DES used !!! ");
    csa->csa_descramble = tvhcsa_des_descramble;
    csa->csa_flush      = tvhcsa_des_flush;
    csa->csa_keylen     = 8;
    break;
  case DESCRAMBLER_AES:
   tvhtrace(LS_CSA, " Encryption AES used !!! ");
    csa->csa_descramble = tvhcsa_aes_descramble;
    csa->csa_flush      = tvhcsa_aes_flush;
    csa->csa_keylen     = 16;
    break;
  default:
    assert(0);
  }
  csa->csa_type = type;
  return 0;
}


void tvhcsa_set_key_even( tvhcsa_t *csa, int index, const uint8_t *even )
{
  switch (csa->csa_type) {
  case DESCRAMBLER_CSA:
#if ENABLE_DVBCSA
    dvbcsa_bs_key_set(even, csa->csa_key_even);
#else
    set_even_control_word((csa)->csa_keys[index], even);
#endif
    break;
  case DESCRAMBLER_DES:
//tvhtrace(LS_CSA, " XXXXXXXXXXXXXXXXXXXX DES even index = %d  ", index);
    des2_set_key(even, csa->csa_des_keys[index][0]);
    break;
  case DESCRAMBLER_AES:
    aes_set_even_control_word(csa->csa_aes_keys, even);
    break;
  default:
    assert(0);
  }
}

void tvhcsa_set_key_odd( tvhcsa_t *csa, int index, const uint8_t *odd )
{
  //assert(csa->csa_type);
  switch (csa->csa_type) {
  case DESCRAMBLER_CSA:
#if ENABLE_DVBCSA
    dvbcsa_bs_key_set(odd, csa->csa_key_odd);
#else
    set_odd_control_word((csa)->csa_keys[index], odd);
#endif
    break;
  case DESCRAMBLER_DES:
//tvhtrace(LS_CSA, " XXXXXXXXXXXXXXXXXXXX DES odd index = %d  ", index);
    des2_set_key(odd, csa->csa_des_keys[index][1]);
    break;
  case DESCRAMBLER_AES:
    aes_set_odd_control_word(csa->csa_aes_keys, odd);
    break;
  default:
    assert(0);
  }
}

void
tvhcsa_init ( tvhcsa_t *csa )
{
  csa->csa_type          = DESCRAMBLER_NONE;
  csa->csa_keylen        = 0;
#if ENABLE_DVBCSA
  csa->csa_cluster_size  = dvbcsa_bs_batch_size();
#else
  csa->csa_cluster_size  = get_suggested_cluster_size();
  csa->csa_cluster_parallelism      = get_internal_parallelism();
#endif
  tvhdebug(LS_CSA, " csa_cluster_size =  %d ", csa->csa_cluster_size);
  /* Note: the optimized routines might read memory after last TS packet */
  /*       allocate safe memory and fill it with zeros */
  csa->csa_tsbcluster    = malloc((csa->csa_cluster_size + 1) * 188);
  memset(csa->csa_tsbcluster + csa->csa_cluster_size * 188, 0, 188);
#if ENABLE_DVBCSA
  csa->csa_tsbbatch_even = malloc((csa->csa_cluster_size + 1) *
                                   sizeof(struct dvbcsa_bs_batch_s));
  csa->csa_tsbbatch_odd  = malloc((csa->csa_cluster_size + 1) *
                                   sizeof(struct dvbcsa_bs_batch_s));
  csa->csa_key_even      = dvbcsa_bs_key_alloc();
  csa->csa_key_odd       = dvbcsa_bs_key_alloc();
#else
  int i;
  for (i = 0; i < MAX_KEYS; i++){
    csa->csa_keys[i]          = get_key_struct();
  }
#endif
  csa->csa_aes_keys      = aes_get_key_struct();
}

void
tvhcsa_destroy ( tvhcsa_t *csa )
{
#if ENABLE_DVBCSA
  dvbcsa_bs_key_free(csa->csa_key_odd);
  dvbcsa_bs_key_free(csa->csa_key_even);
  free(csa->csa_tsbbatch_odd);
  free(csa->csa_tsbbatch_even);
#else
  int i;
  for (i = 0; i < MAX_KEYS; i++){
    free_key_struct(csa->csa_keys[i]);
  }
#endif
  aes_free_key_struct(csa->csa_aes_keys);
  free(csa->csa_tsbcluster);
}
