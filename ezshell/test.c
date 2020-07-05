 struct dirent
{
    long d_ino;                                /* 아이노드 */
    off_t d_off;                                 /* dirent 의 offset */
    unsigned short d_reclen;            /* d_name 의 길이 */
    char d_name ;   /* 파일 이름(없다면 NULL로 종료) */
};



int main(){
  struct dirent di;
  printf("%d",sizeof(di));
    
}

