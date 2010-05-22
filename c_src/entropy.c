/* entropy.c - C code for generating random numbers using the internal windows
   entropy library. 

   Author - nicholasgunder@yahoo.com
   (C) grouphula
   July 1st, 2009
*/

#include <ei.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#define BUF_SIZE 128

#define BYTE unsigned char

/*-----------------------------------------------------------------------------
 * P R O T O T Y P E S
 *---------------------------------------------------------------------------*/
void throw_error(const char* string);
void generate_it(int byte_num, char* byte_store);
int decode_command(char* msg_buff, int* index, int* erlang_version, 
                   int* artiy);
int read_cmd(BYTE *buf, int *size);
int write_cmd(ei_x_buff *buff);
int read_exact(BYTE *buf, int len);
int write_exact(BYTE *buf, int len);
void print_it(BYTE * string); 
/*-----------------------------------------------------------------------------
 * API
 *---------------------------------------------------------------------------*/

void throw_error(const char* string)
{
  ei_x_buff err_result;
  if (ei_x_new_with_version(&err_result) || 
      ei_x_encode_tuple_header(&err_result, 2)) exit(10);
  
  if(ei_x_encode_atom(&err_result, "error") || 
     ei_x_encode_atom(&err_result, string)) exit(11);
  write_cmd(&err_result);
}


void generate_it(int byte_num, char* byte_store) {
#ifdef _WIN32
  HCRYPTPROV hCryptProv;

  if(!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))
    {
      throw_error("crypt_acquire_context_error");
    }

  if(!CryptGenRandom(hCryptProv, byte_num, byte_store))
    {
      throw_error("crypt_gen_random_error");
    }
#else
  FILE* Fp;
  Fp = fopen("/dev/random", "r");
  fread(byte_store, byte_num, 1, Fp);
  fclose(Fp);
#endif
}


/*-----------------------------------------------------------------------------
 *  MAIN
 *---------------------------------------------------------------------------*/
int main()
{
  char* msg_buff;
  int current_buf_size = BUF_SIZE;
  int erlang_version = 0;

  if((msg_buff = (char *)malloc(current_buf_size)) == NULL)
    return -1;

/* Some special setup is needed for windows machines */
#ifdef _WIN32
  setmode(fileno(stdout), O_BINARY);
  setmode(fileno(stdin),  O_BINARY);
#endif

  while(read_cmd(msg_buff, &current_buf_size) >  0)
    {

      /* Reset the index, so that ei functions can decode terms from the 
       * beginning of the buffer */
      int index = 0, arity = 0;
      decode_command(msg_buff, &index, &erlang_version, &arity);
    }
  free(msg_buff);
  return 0;
}

int decode_command(char* msg_buff, int* index, int* erlang_version, int* arity)
{
  unsigned long num_of_bytes;
  unsigned long req_number = 0;
  char command_buffer[100];
  ei_x_buff result;

  /* Ensure that we are receiving the binary term by reading and 
   * stripping the version byte */
  if(ei_decode_version(msg_buff, index, erlang_version)) return 1;

  /* Our marshalling spec is that we are expecting a tuple 
     {entropy_gen, NumBytes} */
  if(ei_decode_tuple_header(msg_buff, index, arity)) return 2;

  if(*arity != 3) 
    {
      throw_error("unsupported_tuple");
      return 3;
    }
  if(ei_decode_atom(msg_buff, index, command_buffer)) return 4;

  if(!strcmp("entropy_gen", command_buffer))
    {
      char* rand_storage = NULL;
      if(ei_decode_ulong(msg_buff, index, &num_of_bytes)) return 5;

      if(ei_decode_ulong(msg_buff, index, &req_number)) return 6;

      rand_storage = malloc(num_of_bytes+1);
      memset(rand_storage, 0, num_of_bytes);
      if(rand_storage == NULL) return 7;
      
      generate_it(num_of_bytes, rand_storage);
      if (ei_x_new_with_version(&result) || 
          ei_x_encode_tuple_header(&result, 3)) return 8;
      
      if(ei_x_encode_atom(&result, "ok_entropy") || 
         ei_x_encode_string_len(&result, rand_storage, num_of_bytes) ||
         ei_x_encode_ulong(&result, req_number))
        return 9;
      write_cmd(&result);
      
      ei_x_free(&result);
      free(rand_storage);
    }
  else
    {
      throw_error("unsupported_tuple");
      return 11;
    }

  return 10;
}


/*-----------------------------------------------------------------------------
 * Erlang Data marshalling functions
 *---------------------------------------------------------------------------*/
int read_cmd(BYTE *buf, int *size)
{
  int len;

  if (read_exact(buf, 2) != 2)
    return(-1);
  len = (buf[0] << 8) | buf[1];

  return read_exact(buf, len);
}

int write_cmd(ei_x_buff *buff)
{
  char li;

  li = (buff->index >> 8) & 0xff; 
  write_exact(&li, 1);
  li = buff->index & 0xff;
  write_exact(&li, 1);

  return write_exact(buff->buff, buff->index);
}

int read_exact(BYTE *buf, int len)
{
  int i, got=0;

  do {
    if ((i = read(0, buf+got, len-got)) <= 0)
      return i;
    got += i;
  } while (got<len);

  return len;
}

int write_exact(BYTE *buf, int len)
{
  int i, wrote = 0;

  do {
    if ((i = write(1, buf+wrote, len-wrote)) <= 0)
      return i;
    wrote += i;
  } while (wrote<len);

  return len;
}


void print_it(BYTE * string) 
{
  FILE * pFile;
  pFile = fopen("C_out.txt", "a+");
  fprintf(pFile, string);
  fclose(pFile);

}
