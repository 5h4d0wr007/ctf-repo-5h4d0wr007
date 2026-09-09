#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NODES 15
#define TABLE_BITS 23
#define TABLE_SIZE (1u << TABLE_BITS)
#define MASK32 0xffffffffu

static uint8_t sbox[256], inv[256];
static uint64_t keys[TABLE_SIZE];
static uint16_t masks[TABLE_SIZE];
static uint32_t paths[TABLE_SIZE];

static uint32_t mix(uint64_t x) { x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33; return (uint32_t)x; }
static uint8_t rol3(uint8_t x) { return (uint8_t)((x << 3) | (x >> 5)); }
static uint32_t hf(uint32_t h, uint8_t i, uint8_t t, uint8_t u) { h = (h ^ t) * 0x01000193u; return (h ^ ((uint32_t)u << 8 | i)) * 0x01000193u; }
static uint32_t hr(uint32_t h, uint8_t i, uint8_t t, uint8_t u) { h = h * 0x359c449bu ^ ((uint32_t)u << 8 | i); return h * 0x359c449bu ^ t; }
static uint64_t key(uint8_t i, uint8_t st, uint32_t h) { return ((uint64_t)h << 16) | ((uint64_t)st << 8) | i | 1ULL; }

static void put(uint8_t i, uint8_t st, uint32_t h, uint16_t mask, uint32_t path) {
  uint64_t k = key(i,st,h); uint32_t p = mix(k) & (TABLE_SIZE-1);
  while (keys[p] && keys[p] != k) p = (p+1) & (TABLE_SIZE-1);
  if (!keys[p]) { keys[p]=k; masks[p]=mask; paths[p]=path; }
}
static int get(uint8_t i, uint8_t st, uint32_t h, uint16_t bm, uint16_t *fm, uint32_t *fp) {
  uint64_t k = key(i,st,h); uint32_t p = mix(k) & (TABLE_SIZE-1);
  while (keys[p]) { if (keys[p] == k) { if (!(masks[p] & bm)) { *fm=masks[p]; *fp=paths[p]; return 1; } return 0; } p=(p+1)&(TABLE_SIZE-1); }
  return 0;
}

static void forward(int depth, uint8_t i, uint8_t st, uint32_t h, uint16_t mask, uint32_t path) {
  if (depth == 6) { put(i,st,h,mask,path); return; }
  for (int n=0;n<NODES;n++) if (!(mask & (1u<<n))) {
    uint8_t j=(uint8_t)(16+n), u=(uint8_t)(j-i), t=inv[u]^st^i;
    uint8_t a=t^sbox[rol3(st)]; if (!a) continue;
    forward(depth+1,j,t^u,hf(h,i,t,u),mask|(1u<<n),path|((uint32_t)n<<(4*depth)));
  }
}

static int found;
static void report(uint32_t fp, uint8_t back[5], uint8_t midpoint_state) {
  uint8_t nodes[12]; nodes[0]=19;
  for(int d=0;d<6;d++) nodes[d+1]=(uint8_t)(16+((fp>>(4*d))&15));
  for(int d=0;d<4;d++) nodes[7+d]=back[3-d];
  nodes[11]=32;
  uint8_t out[32]; memset(out,'A',sizeof(out)); memcpy(out,"IATCQ{",6); out[31]='}';
  uint8_t st=0; uint32_t h=0xeb76ad9a;
  for(int d=0;d<11;d++) { uint8_t i=nodes[d],j=nodes[d+1],u=(uint8_t)(j-i),t=inv[u]^st^i,a=t^sbox[rol3(st)]; out[i]=a; st=t^u; h=hf(h,i,t,u); }
  (void)midpoint_state;
  if (h != 0x86d03165u) return;
  printf("path:"); for(int d=0;d<12;d++) printf(" %u",nodes[d]); puts("");
  printf("hex:"); for(int i=0;i<32;i++) printf("%02x",out[i]); puts("");
  printf("key: "); for(int i=0;i<32;i++) putchar(out[i]>=32&&out[i]<127?out[i]:'.'); puts("");
  found=1;
}

static void backward(int depth, uint8_t j, uint8_t stj, uint32_t hj, uint16_t mask, uint8_t back[5]) {
  if (found) return;
  if (depth == 5) { uint16_t fm; uint32_t fp; uint16_t prior = mask & ~(1u << (j - 16)); if (get(j,stj,hj,prior,&fm,&fp)) report(fp,back,stj); return; }
  for(int n=0;n<NODES;n++) if (!(mask&(1u<<n))) {
    uint8_t i=(uint8_t)(16+n),u=(uint8_t)(j-i),sti=stj^inv[u]^i^u,t=inv[u]^sti^i;
    uint8_t a=t^sbox[rol3(sti)]; if (!a) continue;
    back[depth]=i; backward(depth+1,i,sti,hr(hj,i,t,u),mask|(1u<<n),back); if(found)return;
  }
}

int main(void) {
  FILE *f=fopen("/tmp/hyperstate4","rb"); if(!f)return 1; fseek(f,0x20c0,SEEK_SET);
  uint32_t seed=0xc0ffee42; for(int i=0;i<256;i++){int c=fgetc(f);seed=seed*0x41c64e6d+0x3039;sbox[i]=(uint8_t)c^(seed>>16);} fclose(f);
  for(int i=0;i<256;i++)inv[sbox[i]]=i;
  forward(0,19,0,0xeb76ad9a,1u<<(19-16),0);
  fprintf(stderr,"forward table built\n");
  uint8_t back[5]; for(int st=0;st<256&&!found;st++) backward(0,32,(uint8_t)st,0x86d03165,0,back);
  return found?0:2;
}
