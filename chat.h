void clear_screen();
unsigned char get_username(unsigned char *username);

typedef struct _evlt_chat {
 evlt_vault *v;
 evlt_vector *vc;
 struct stat previous_attrs;
} evlt_chat;