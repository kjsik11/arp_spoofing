#include <stdio.h>
#include <pcap.h>
#include <string.h>

static void input_ip(u_int8_t *ip,char str[]){
    int temp=0;
    for(int i=0;i<4;i++){

        int tmp=0;
        for(int j=0;j<3;j++){
            if('0'<=str[temp+j]&&str[temp+j]<='9')
                tmp++;
            else
                break;
        }
        if(tmp==2){
            //0 ~ 1 == 48 ~ 57
            int dcm_tmp =0;
            dcm_tmp+=(str[temp+0]-48)*10;
            dcm_tmp+=(str[temp+1]-48);

            //c language word list coding
            if(dcm_tmp==0)ip[i]=0x00;if(dcm_tmp==1)ip[i]=0x01;if(dcm_tmp==2)ip[i]=0x02;if(dcm_tmp==3)ip[i]=0x03;if(dcm_tmp==4)ip[i]=0x04;if(dcm_tmp==5)ip[i]=0x05;if(dcm_tmp==6)ip[i]=0x06;if(dcm_tmp==7)ip[i]=0x07;if(dcm_tmp==8)ip[i]=0x08;if(dcm_tmp==9)ip[i]=0x09;if(dcm_tmp==10)ip[i]=0x0a;if(dcm_tmp==11)ip[i]=0x0b;if(dcm_tmp==12)ip[i]=0x0c;if(dcm_tmp==13)ip[i]=0x0d;if(dcm_tmp==14)ip[i]=0x0e;if(dcm_tmp==15)ip[i]=0x0f;if(dcm_tmp==16)ip[i]=0x10;if(dcm_tmp==17)ip[i]=0x11;if(dcm_tmp==18)ip[i]=0x12;if(dcm_tmp==19)ip[i]=0x13;if(dcm_tmp==20)ip[i]=0x14;if(dcm_tmp==21)ip[i]=0x15;if(dcm_tmp==22)ip[i]=0x16;if(dcm_tmp==23)ip[i]=0x17;if(dcm_tmp==24)ip[i]=0x18;if(dcm_tmp==25)ip[i]=0x19;if(dcm_tmp==26)ip[i]=0x1a;if(dcm_tmp==27)ip[i]=0x1b;if(dcm_tmp==28)ip[i]=0x1c;if(dcm_tmp==29)ip[i]=0x1d;if(dcm_tmp==30)ip[i]=0x1e;if(dcm_tmp==31)ip[i]=0x1f;if(dcm_tmp==32)ip[i]=0x20;if(dcm_tmp==33)ip[i]=0x21;if(dcm_tmp==34)ip[i]=0x22;if(dcm_tmp==35)ip[i]=0x23;if(dcm_tmp==36)ip[i]=0x24;if(dcm_tmp==37)ip[i]=0x25;if(dcm_tmp==38)ip[i]=0x26;if(dcm_tmp==39)ip[i]=0x27;if(dcm_tmp==40)ip[i]=0x28;if(dcm_tmp==41)ip[i]=0x29;if(dcm_tmp==42)ip[i]=0x2a;if(dcm_tmp==43)ip[i]=0x2b;if(dcm_tmp==44)ip[i]=0x2c;if(dcm_tmp==45)ip[i]=0x2d;if(dcm_tmp==46)ip[i]=0x2e;if(dcm_tmp==47)ip[i]=0x2f;if(dcm_tmp==48)ip[i]=0x30;if(dcm_tmp==49)ip[i]=0x31;if(dcm_tmp==50)ip[i]=0x32;if(dcm_tmp==51)ip[i]=0x33;if(dcm_tmp==52)ip[i]=0x34;if(dcm_tmp==53)ip[i]=0x35;if(dcm_tmp==54)ip[i]=0x36;if(dcm_tmp==55)ip[i]=0x37;if(dcm_tmp==56)ip[i]=0x38;if(dcm_tmp==57)ip[i]=0x39;if(dcm_tmp==58)ip[i]=0x3a;if(dcm_tmp==59)ip[i]=0x3b;if(dcm_tmp==60)ip[i]=0x3c;if(dcm_tmp==61)ip[i]=0x3d;if(dcm_tmp==62)ip[i]=0x3e;if(dcm_tmp==63)ip[i]=0x3f;if(dcm_tmp==64)ip[i]=0x40;if(dcm_tmp==65)ip[i]=0x41;if(dcm_tmp==66)ip[i]=0x42;if(dcm_tmp==67)ip[i]=0x43;if(dcm_tmp==68)ip[i]=0x44;if(dcm_tmp==69)ip[i]=0x45;if(dcm_tmp==70)ip[i]=0x46;if(dcm_tmp==71)ip[i]=0x47;if(dcm_tmp==72)ip[i]=0x48;if(dcm_tmp==73)ip[i]=0x49;if(dcm_tmp==74)ip[i]=0x4a;if(dcm_tmp==75)ip[i]=0x4b;if(dcm_tmp==76)ip[i]=0x4c;if(dcm_tmp==77)ip[i]=0x4d;if(dcm_tmp==78)ip[i]=0x4e;if(dcm_tmp==79)ip[i]=0x4f;if(dcm_tmp==80)ip[i]=0x50;if(dcm_tmp==81)ip[i]=0x51;if(dcm_tmp==82)ip[i]=0x52;if(dcm_tmp==83)ip[i]=0x53;if(dcm_tmp==84)ip[i]=0x54;if(dcm_tmp==85)ip[i]=0x55;if(dcm_tmp==86)ip[i]=0x56;if(dcm_tmp==87)ip[i]=0x57;if(dcm_tmp==88)ip[i]=0x58;if(dcm_tmp==89)ip[i]=0x59;if(dcm_tmp==90)ip[i]=0x5a;if(dcm_tmp==91)ip[i]=0x5b;if(dcm_tmp==92)ip[i]=0x5c;if(dcm_tmp==93)ip[i]=0x5d;if(dcm_tmp==94)ip[i]=0x5e;if(dcm_tmp==95)ip[i]=0x5f;if(dcm_tmp==96)ip[i]=0x60;if(dcm_tmp==97)ip[i]=0x61;if(dcm_tmp==98)ip[i]=0x62;if(dcm_tmp==99)ip[i]=0x63;if(dcm_tmp==100)ip[i]=0x64;if(dcm_tmp==101)ip[i]=0x65;if(dcm_tmp==102)ip[i]=0x66;if(dcm_tmp==103)ip[i]=0x67;if(dcm_tmp==104)ip[i]=0x68;if(dcm_tmp==105)ip[i]=0x69;if(dcm_tmp==106)ip[i]=0x6a;if(dcm_tmp==107)ip[i]=0x6b;if(dcm_tmp==108)ip[i]=0x6c;if(dcm_tmp==109)ip[i]=0x6d;if(dcm_tmp==110)ip[i]=0x6e;if(dcm_tmp==111)ip[i]=0x6f;if(dcm_tmp==112)ip[i]=0x70;if(dcm_tmp==113)ip[i]=0x71;if(dcm_tmp==114)ip[i]=0x72;if(dcm_tmp==115)ip[i]=0x73;if(dcm_tmp==116)ip[i]=0x74;if(dcm_tmp==117)ip[i]=0x75;if(dcm_tmp==118)ip[i]=0x76;if(dcm_tmp==119)ip[i]=0x77;if(dcm_tmp==120)ip[i]=0x78;if(dcm_tmp==121)ip[i]=0x79;if(dcm_tmp==122)ip[i]=0x7a;if(dcm_tmp==123)ip[i]=0x7b;if(dcm_tmp==124)ip[i]=0x7c;if(dcm_tmp==125)ip[i]=0x7d;if(dcm_tmp==126)ip[i]=0x7e;if(dcm_tmp==127)ip[i]=0x7f;if(dcm_tmp==128)ip[i]=0x80;if(dcm_tmp==129)ip[i]=0x81;if(dcm_tmp==130)ip[i]=0x82;if(dcm_tmp==131)ip[i]=0x83;if(dcm_tmp==132)ip[i]=0x84;if(dcm_tmp==133)ip[i]=0x85;if(dcm_tmp==134)ip[i]=0x86;if(dcm_tmp==135)ip[i]=0x87;if(dcm_tmp==136)ip[i]=0x88;if(dcm_tmp==137)ip[i]=0x89;if(dcm_tmp==138)ip[i]=0x8a;if(dcm_tmp==139)ip[i]=0x8b;if(dcm_tmp==140)ip[i]=0x8c;if(dcm_tmp==141)ip[i]=0x8d;if(dcm_tmp==142)ip[i]=0x8e;if(dcm_tmp==143)ip[i]=0x8f;if(dcm_tmp==144)ip[i]=0x90;if(dcm_tmp==145)ip[i]=0x91;if(dcm_tmp==146)ip[i]=0x92;if(dcm_tmp==147)ip[i]=0x93;if(dcm_tmp==148)ip[i]=0x94;if(dcm_tmp==149)ip[i]=0x95;if(dcm_tmp==150)ip[i]=0x96;if(dcm_tmp==151)ip[i]=0x97;if(dcm_tmp==152)ip[i]=0x98;if(dcm_tmp==153)ip[i]=0x99;if(dcm_tmp==154)ip[i]=0x9a;if(dcm_tmp==155)ip[i]=0x9b;if(dcm_tmp==156)ip[i]=0x9c;if(dcm_tmp==157)ip[i]=0x9d;if(dcm_tmp==158)ip[i]=0x9e;if(dcm_tmp==159)ip[i]=0x9f;if(dcm_tmp==160)ip[i]=0xa0;if(dcm_tmp==161)ip[i]=0xa1;if(dcm_tmp==162)ip[i]=0xa2;if(dcm_tmp==163)ip[i]=0xa3;if(dcm_tmp==164)ip[i]=0xa4;if(dcm_tmp==165)ip[i]=0xa5;if(dcm_tmp==166)ip[i]=0xa6;if(dcm_tmp==167)ip[i]=0xa7;if(dcm_tmp==168)ip[i]=0xa8;if(dcm_tmp==169)ip[i]=0xa9;if(dcm_tmp==170)ip[i]=0xaa;if(dcm_tmp==171)ip[i]=0xab;if(dcm_tmp==172)ip[i]=0xac;if(dcm_tmp==173)ip[i]=0xad;if(dcm_tmp==174)ip[i]=0xae;if(dcm_tmp==175)ip[i]=0xaf;if(dcm_tmp==176)ip[i]=0xb0;if(dcm_tmp==177)ip[i]=0xb1;if(dcm_tmp==178)ip[i]=0xb2;if(dcm_tmp==179)ip[i]=0xb3;if(dcm_tmp==180)ip[i]=0xb4;if(dcm_tmp==181)ip[i]=0xb5;if(dcm_tmp==182)ip[i]=0xb6;if(dcm_tmp==183)ip[i]=0xb7;if(dcm_tmp==184)ip[i]=0xb8;if(dcm_tmp==185)ip[i]=0xb9;if(dcm_tmp==186)ip[i]=0xba;if(dcm_tmp==187)ip[i]=0xbb;if(dcm_tmp==188)ip[i]=0xbc;if(dcm_tmp==189)ip[i]=0xbd;if(dcm_tmp==190)ip[i]=0xbe;if(dcm_tmp==191)ip[i]=0xbf;if(dcm_tmp==192)ip[i]=0xc0;if(dcm_tmp==193)ip[i]=0xc1;if(dcm_tmp==194)ip[i]=0xc2;if(dcm_tmp==195)ip[i]=0xc3;if(dcm_tmp==196)ip[i]=0xc4;if(dcm_tmp==197)ip[i]=0xc5;if(dcm_tmp==198)ip[i]=0xc6;if(dcm_tmp==199)ip[i]=0xc7;if(dcm_tmp==200)ip[i]=0xc8;if(dcm_tmp==201)ip[i]=0xc9;if(dcm_tmp==202)ip[i]=0xca;if(dcm_tmp==203)ip[i]=0xcb;if(dcm_tmp==204)ip[i]=0xcc;if(dcm_tmp==205)ip[i]=0xcd;if(dcm_tmp==206)ip[i]=0xce;if(dcm_tmp==207)ip[i]=0xcf;if(dcm_tmp==208)ip[i]=0xd0;if(dcm_tmp==209)ip[i]=0xd1;if(dcm_tmp==210)ip[i]=0xd2;if(dcm_tmp==211)ip[i]=0xd3;if(dcm_tmp==212)ip[i]=0xd4;if(dcm_tmp==213)ip[i]=0xd5;if(dcm_tmp==214)ip[i]=0xd6;if(dcm_tmp==215)ip[i]=0xd7;if(dcm_tmp==216)ip[i]=0xd8;if(dcm_tmp==217)ip[i]=0xd9;if(dcm_tmp==218)ip[i]=0xda;if(dcm_tmp==219)ip[i]=0xdb;if(dcm_tmp==220)ip[i]=0xdc;if(dcm_tmp==221)ip[i]=0xdd;if(dcm_tmp==222)ip[i]=0xde;if(dcm_tmp==223)ip[i]=0xdf;if(dcm_tmp==224)ip[i]=0xe0;if(dcm_tmp==225)ip[i]=0xe1;if(dcm_tmp==226)ip[i]=0xe2;if(dcm_tmp==227)ip[i]=0xe3;if(dcm_tmp==228)ip[i]=0xe4;if(dcm_tmp==229)ip[i]=0xe5;if(dcm_tmp==230)ip[i]=0xe6;if(dcm_tmp==231)ip[i]=0xe7;if(dcm_tmp==232)ip[i]=0xe8;if(dcm_tmp==233)ip[i]=0xe9;if(dcm_tmp==234)ip[i]=0xea;if(dcm_tmp==235)ip[i]=0xeb;if(dcm_tmp==236)ip[i]=0xec;if(dcm_tmp==237)ip[i]=0xed;if(dcm_tmp==238)ip[i]=0xee;if(dcm_tmp==239)ip[i]=0xef;if(dcm_tmp==240)ip[i]=0xf0;if(dcm_tmp==241)ip[i]=0xf1;if(dcm_tmp==242)ip[i]=0xf2;if(dcm_tmp==243)ip[i]=0xf3;if(dcm_tmp==244)ip[i]=0xf4;if(dcm_tmp==245)ip[i]=0xf5;if(dcm_tmp==246)ip[i]=0xf6;if(dcm_tmp==247)ip[i]=0xf7;if(dcm_tmp==248)ip[i]=0xf8;if(dcm_tmp==249)ip[i]=0xf9;if(dcm_tmp==250)ip[i]=0xfa;if(dcm_tmp==251)ip[i]=0xfb;if(dcm_tmp==252)ip[i]=0xfc;if(dcm_tmp==253)ip[i]=0xfd;if(dcm_tmp==254)ip[i]=0xfe;if(dcm_tmp==255)ip[i]=0xff;

        }
        else{
            int dcm_tmp =0;
            dcm_tmp+=(str[temp+0]-48)*100;
            dcm_tmp+=(str[temp+1]-48)*10;
            dcm_tmp+=(str[temp+2]-48);

             //c language word list coding
            if(dcm_tmp==0)ip[i]=0x00;if(dcm_tmp==1)ip[i]=0x01;if(dcm_tmp==2)ip[i]=0x02;if(dcm_tmp==3)ip[i]=0x03;if(dcm_tmp==4)ip[i]=0x04;if(dcm_tmp==5)ip[i]=0x05;if(dcm_tmp==6)ip[i]=0x06;if(dcm_tmp==7)ip[i]=0x07;if(dcm_tmp==8)ip[i]=0x08;if(dcm_tmp==9)ip[i]=0x09;if(dcm_tmp==10)ip[i]=0x0a;if(dcm_tmp==11)ip[i]=0x0b;if(dcm_tmp==12)ip[i]=0x0c;if(dcm_tmp==13)ip[i]=0x0d;if(dcm_tmp==14)ip[i]=0x0e;if(dcm_tmp==15)ip[i]=0x0f;if(dcm_tmp==16)ip[i]=0x10;if(dcm_tmp==17)ip[i]=0x11;if(dcm_tmp==18)ip[i]=0x12;if(dcm_tmp==19)ip[i]=0x13;if(dcm_tmp==20)ip[i]=0x14;if(dcm_tmp==21)ip[i]=0x15;if(dcm_tmp==22)ip[i]=0x16;if(dcm_tmp==23)ip[i]=0x17;if(dcm_tmp==24)ip[i]=0x18;if(dcm_tmp==25)ip[i]=0x19;if(dcm_tmp==26)ip[i]=0x1a;if(dcm_tmp==27)ip[i]=0x1b;if(dcm_tmp==28)ip[i]=0x1c;if(dcm_tmp==29)ip[i]=0x1d;if(dcm_tmp==30)ip[i]=0x1e;if(dcm_tmp==31)ip[i]=0x1f;if(dcm_tmp==32)ip[i]=0x20;if(dcm_tmp==33)ip[i]=0x21;if(dcm_tmp==34)ip[i]=0x22;if(dcm_tmp==35)ip[i]=0x23;if(dcm_tmp==36)ip[i]=0x24;if(dcm_tmp==37)ip[i]=0x25;if(dcm_tmp==38)ip[i]=0x26;if(dcm_tmp==39)ip[i]=0x27;if(dcm_tmp==40)ip[i]=0x28;if(dcm_tmp==41)ip[i]=0x29;if(dcm_tmp==42)ip[i]=0x2a;if(dcm_tmp==43)ip[i]=0x2b;if(dcm_tmp==44)ip[i]=0x2c;if(dcm_tmp==45)ip[i]=0x2d;if(dcm_tmp==46)ip[i]=0x2e;if(dcm_tmp==47)ip[i]=0x2f;if(dcm_tmp==48)ip[i]=0x30;if(dcm_tmp==49)ip[i]=0x31;if(dcm_tmp==50)ip[i]=0x32;if(dcm_tmp==51)ip[i]=0x33;if(dcm_tmp==52)ip[i]=0x34;if(dcm_tmp==53)ip[i]=0x35;if(dcm_tmp==54)ip[i]=0x36;if(dcm_tmp==55)ip[i]=0x37;if(dcm_tmp==56)ip[i]=0x38;if(dcm_tmp==57)ip[i]=0x39;if(dcm_tmp==58)ip[i]=0x3a;if(dcm_tmp==59)ip[i]=0x3b;if(dcm_tmp==60)ip[i]=0x3c;if(dcm_tmp==61)ip[i]=0x3d;if(dcm_tmp==62)ip[i]=0x3e;if(dcm_tmp==63)ip[i]=0x3f;if(dcm_tmp==64)ip[i]=0x40;if(dcm_tmp==65)ip[i]=0x41;if(dcm_tmp==66)ip[i]=0x42;if(dcm_tmp==67)ip[i]=0x43;if(dcm_tmp==68)ip[i]=0x44;if(dcm_tmp==69)ip[i]=0x45;if(dcm_tmp==70)ip[i]=0x46;if(dcm_tmp==71)ip[i]=0x47;if(dcm_tmp==72)ip[i]=0x48;if(dcm_tmp==73)ip[i]=0x49;if(dcm_tmp==74)ip[i]=0x4a;if(dcm_tmp==75)ip[i]=0x4b;if(dcm_tmp==76)ip[i]=0x4c;if(dcm_tmp==77)ip[i]=0x4d;if(dcm_tmp==78)ip[i]=0x4e;if(dcm_tmp==79)ip[i]=0x4f;if(dcm_tmp==80)ip[i]=0x50;if(dcm_tmp==81)ip[i]=0x51;if(dcm_tmp==82)ip[i]=0x52;if(dcm_tmp==83)ip[i]=0x53;if(dcm_tmp==84)ip[i]=0x54;if(dcm_tmp==85)ip[i]=0x55;if(dcm_tmp==86)ip[i]=0x56;if(dcm_tmp==87)ip[i]=0x57;if(dcm_tmp==88)ip[i]=0x58;if(dcm_tmp==89)ip[i]=0x59;if(dcm_tmp==90)ip[i]=0x5a;if(dcm_tmp==91)ip[i]=0x5b;if(dcm_tmp==92)ip[i]=0x5c;if(dcm_tmp==93)ip[i]=0x5d;if(dcm_tmp==94)ip[i]=0x5e;if(dcm_tmp==95)ip[i]=0x5f;if(dcm_tmp==96)ip[i]=0x60;if(dcm_tmp==97)ip[i]=0x61;if(dcm_tmp==98)ip[i]=0x62;if(dcm_tmp==99)ip[i]=0x63;if(dcm_tmp==100)ip[i]=0x64;if(dcm_tmp==101)ip[i]=0x65;if(dcm_tmp==102)ip[i]=0x66;if(dcm_tmp==103)ip[i]=0x67;if(dcm_tmp==104)ip[i]=0x68;if(dcm_tmp==105)ip[i]=0x69;if(dcm_tmp==106)ip[i]=0x6a;if(dcm_tmp==107)ip[i]=0x6b;if(dcm_tmp==108)ip[i]=0x6c;if(dcm_tmp==109)ip[i]=0x6d;if(dcm_tmp==110)ip[i]=0x6e;if(dcm_tmp==111)ip[i]=0x6f;if(dcm_tmp==112)ip[i]=0x70;if(dcm_tmp==113)ip[i]=0x71;if(dcm_tmp==114)ip[i]=0x72;if(dcm_tmp==115)ip[i]=0x73;if(dcm_tmp==116)ip[i]=0x74;if(dcm_tmp==117)ip[i]=0x75;if(dcm_tmp==118)ip[i]=0x76;if(dcm_tmp==119)ip[i]=0x77;if(dcm_tmp==120)ip[i]=0x78;if(dcm_tmp==121)ip[i]=0x79;if(dcm_tmp==122)ip[i]=0x7a;if(dcm_tmp==123)ip[i]=0x7b;if(dcm_tmp==124)ip[i]=0x7c;if(dcm_tmp==125)ip[i]=0x7d;if(dcm_tmp==126)ip[i]=0x7e;if(dcm_tmp==127)ip[i]=0x7f;if(dcm_tmp==128)ip[i]=0x80;if(dcm_tmp==129)ip[i]=0x81;if(dcm_tmp==130)ip[i]=0x82;if(dcm_tmp==131)ip[i]=0x83;if(dcm_tmp==132)ip[i]=0x84;if(dcm_tmp==133)ip[i]=0x85;if(dcm_tmp==134)ip[i]=0x86;if(dcm_tmp==135)ip[i]=0x87;if(dcm_tmp==136)ip[i]=0x88;if(dcm_tmp==137)ip[i]=0x89;if(dcm_tmp==138)ip[i]=0x8a;if(dcm_tmp==139)ip[i]=0x8b;if(dcm_tmp==140)ip[i]=0x8c;if(dcm_tmp==141)ip[i]=0x8d;if(dcm_tmp==142)ip[i]=0x8e;if(dcm_tmp==143)ip[i]=0x8f;if(dcm_tmp==144)ip[i]=0x90;if(dcm_tmp==145)ip[i]=0x91;if(dcm_tmp==146)ip[i]=0x92;if(dcm_tmp==147)ip[i]=0x93;if(dcm_tmp==148)ip[i]=0x94;if(dcm_tmp==149)ip[i]=0x95;if(dcm_tmp==150)ip[i]=0x96;if(dcm_tmp==151)ip[i]=0x97;if(dcm_tmp==152)ip[i]=0x98;if(dcm_tmp==153)ip[i]=0x99;if(dcm_tmp==154)ip[i]=0x9a;if(dcm_tmp==155)ip[i]=0x9b;if(dcm_tmp==156)ip[i]=0x9c;if(dcm_tmp==157)ip[i]=0x9d;if(dcm_tmp==158)ip[i]=0x9e;if(dcm_tmp==159)ip[i]=0x9f;if(dcm_tmp==160)ip[i]=0xa0;if(dcm_tmp==161)ip[i]=0xa1;if(dcm_tmp==162)ip[i]=0xa2;if(dcm_tmp==163)ip[i]=0xa3;if(dcm_tmp==164)ip[i]=0xa4;if(dcm_tmp==165)ip[i]=0xa5;if(dcm_tmp==166)ip[i]=0xa6;if(dcm_tmp==167)ip[i]=0xa7;if(dcm_tmp==168)ip[i]=0xa8;if(dcm_tmp==169)ip[i]=0xa9;if(dcm_tmp==170)ip[i]=0xaa;if(dcm_tmp==171)ip[i]=0xab;if(dcm_tmp==172)ip[i]=0xac;if(dcm_tmp==173)ip[i]=0xad;if(dcm_tmp==174)ip[i]=0xae;if(dcm_tmp==175)ip[i]=0xaf;if(dcm_tmp==176)ip[i]=0xb0;if(dcm_tmp==177)ip[i]=0xb1;if(dcm_tmp==178)ip[i]=0xb2;if(dcm_tmp==179)ip[i]=0xb3;if(dcm_tmp==180)ip[i]=0xb4;if(dcm_tmp==181)ip[i]=0xb5;if(dcm_tmp==182)ip[i]=0xb6;if(dcm_tmp==183)ip[i]=0xb7;if(dcm_tmp==184)ip[i]=0xb8;if(dcm_tmp==185)ip[i]=0xb9;if(dcm_tmp==186)ip[i]=0xba;if(dcm_tmp==187)ip[i]=0xbb;if(dcm_tmp==188)ip[i]=0xbc;if(dcm_tmp==189)ip[i]=0xbd;if(dcm_tmp==190)ip[i]=0xbe;if(dcm_tmp==191)ip[i]=0xbf;if(dcm_tmp==192)ip[i]=0xc0;if(dcm_tmp==193)ip[i]=0xc1;if(dcm_tmp==194)ip[i]=0xc2;if(dcm_tmp==195)ip[i]=0xc3;if(dcm_tmp==196)ip[i]=0xc4;if(dcm_tmp==197)ip[i]=0xc5;if(dcm_tmp==198)ip[i]=0xc6;if(dcm_tmp==199)ip[i]=0xc7;if(dcm_tmp==200)ip[i]=0xc8;if(dcm_tmp==201)ip[i]=0xc9;if(dcm_tmp==202)ip[i]=0xca;if(dcm_tmp==203)ip[i]=0xcb;if(dcm_tmp==204)ip[i]=0xcc;if(dcm_tmp==205)ip[i]=0xcd;if(dcm_tmp==206)ip[i]=0xce;if(dcm_tmp==207)ip[i]=0xcf;if(dcm_tmp==208)ip[i]=0xd0;if(dcm_tmp==209)ip[i]=0xd1;if(dcm_tmp==210)ip[i]=0xd2;if(dcm_tmp==211)ip[i]=0xd3;if(dcm_tmp==212)ip[i]=0xd4;if(dcm_tmp==213)ip[i]=0xd5;if(dcm_tmp==214)ip[i]=0xd6;if(dcm_tmp==215)ip[i]=0xd7;if(dcm_tmp==216)ip[i]=0xd8;if(dcm_tmp==217)ip[i]=0xd9;if(dcm_tmp==218)ip[i]=0xda;if(dcm_tmp==219)ip[i]=0xdb;if(dcm_tmp==220)ip[i]=0xdc;if(dcm_tmp==221)ip[i]=0xdd;if(dcm_tmp==222)ip[i]=0xde;if(dcm_tmp==223)ip[i]=0xdf;if(dcm_tmp==224)ip[i]=0xe0;if(dcm_tmp==225)ip[i]=0xe1;if(dcm_tmp==226)ip[i]=0xe2;if(dcm_tmp==227)ip[i]=0xe3;if(dcm_tmp==228)ip[i]=0xe4;if(dcm_tmp==229)ip[i]=0xe5;if(dcm_tmp==230)ip[i]=0xe6;if(dcm_tmp==231)ip[i]=0xe7;if(dcm_tmp==232)ip[i]=0xe8;if(dcm_tmp==233)ip[i]=0xe9;if(dcm_tmp==234)ip[i]=0xea;if(dcm_tmp==235)ip[i]=0xeb;if(dcm_tmp==236)ip[i]=0xec;if(dcm_tmp==237)ip[i]=0xed;if(dcm_tmp==238)ip[i]=0xee;if(dcm_tmp==239)ip[i]=0xef;if(dcm_tmp==240)ip[i]=0xf0;if(dcm_tmp==241)ip[i]=0xf1;if(dcm_tmp==242)ip[i]=0xf2;if(dcm_tmp==243)ip[i]=0xf3;if(dcm_tmp==244)ip[i]=0xf4;if(dcm_tmp==245)ip[i]=0xf5;if(dcm_tmp==246)ip[i]=0xf6;if(dcm_tmp==247)ip[i]=0xf7;if(dcm_tmp==248)ip[i]=0xf8;if(dcm_tmp==249)ip[i]=0xf9;if(dcm_tmp==250)ip[i]=0xfa;if(dcm_tmp==251)ip[i]=0xfb;if(dcm_tmp==252)ip[i]=0xfc;if(dcm_tmp==253)ip[i]=0xfd;if(dcm_tmp==254)ip[i]=0xfe;if(dcm_tmp==255)ip[i]=0xff;

        }
        temp+=tmp+1;
    }
}
