#include/*
#<?php echo file_get_contents('./flag.txt'); ?>

q="""*/<stdlib.h>
#define xstr(s) str(s)
#define str(s) #s
#define command cat flag.txt
int main(){system(xstr(command));}/*=;
open(FH,'<','flag.txt');print <FH>;#";exec('cat flag.txt')#""";print(open('flag.txt').read())#*/