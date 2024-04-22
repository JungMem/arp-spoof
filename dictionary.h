// https://qwerty-ojjj.tistory.com/14
#include "ip.h"

typedef struct _DICTIONARY {
    char* key;
    uint8_t value[6];
    struct _DICTIONARY* link;

}_dictionary;

typedef struct DICTIONARY {
    int count;
    struct _DICTIONARY* head;
}dictionary;

void DICT_Show(dictionary dic) {
    _dictionary* temp = dic.head;
    int i=0;

    printf("--- total count : %d\n", dic.count);
    while (temp != NULL) {
        printf("[%d] %s ", i, temp->key);
        for(int j=0; j<6; j++) printf("%02X.", temp->value[j]);
        printf("\n");
        i++; temp = temp->link;
    }
}

bool DICT_Check(dictionary dic, uint32_t key){
    
    char tmp[20] = {0, };
    sprintf(tmp, "%u.%u.%u.%u",
		(key & 0x000000FF),
		(key & 0x0000FF00) >> 8,
		(key & 0x00FF0000) >> 16,
		(key & 0xFF000000) >> 24);

    _dictionary* temp = dic.head;
    while (temp != NULL){
        if(strcmp(temp->key, tmp) == 0) return true;
        
        temp = temp->link;
    }
    return false;
    
}

void DICT_Load(dictionary dic, char* key, uint8_t* buf) {
    _dictionary* temp = dic.head;

    while (temp != NULL) {
    
    	if(strcmp(temp->key, key) == 0) memcpy(buf, temp->value, 6);

        temp = temp->link;
    }
    
}

void DICT_Add(dictionary* head, char* key, uint8_t* value) {
    _dictionary* temp = head->head;

    while (1) {

        if (head->count == 0/*temp == NULL*/) {
            temp = (_dictionary*)malloc(sizeof(_dictionary));
            //temp->key = StringAdd1("", key);
            temp->key = key;
            memcpy(temp->value, value, 6);
            temp->link = NULL;
            head->head = temp;
            break;
        }


        else if (strcmp(temp->key, key) == 0) {
            return;
        }


        else if (temp->link == NULL) {
            temp->link = (_dictionary*)malloc(sizeof(_dictionary));
            //temp->link->key = StringAdd1("", key);
            temp->link->key = key;
            memcpy(temp->link->value, value, 6);
            temp->link->link = NULL;
            break;
        }


        else {
            temp = temp->link;
        }
    }
    head->count++;

}
