#!/bin/bash
# Run ./sir@cmpwn.com
# Arrow keys or wasd to move

c=`tput cols`;L=`tput lines`
let x=$c/2;let y=$L/2;d=0;le=3;t="$y;$x";i=0;j=0;S=0
A(){ let i=($RANDOM%$c);let j=($RANDOM%$L);};A
B(){ printf $*;};C(){ B "\x1B[$1";};D(){ C "$1H";}
F(){ D "0;0";C 2J;C "?25h";printf "GAME OVER\nSCORE: $S\n";exit;};trap F INT
C ?25l;C 2J;da(){ D "$j;$i";echo "$1";}
G() { for n in $t; do D "$n";echo "$1";done;}
mt(){ t=`echo "$t"|cut -d' ' -f2-`;}
sc(){ D "0;0";echo "Score: $S"; }
gt() { t+=" $y;$x";};ct() { for n in $t; do [ "$y;$x" == "$n" ]&&F;done;}
M() { case $d in 0)let y--;;1)let x--;;2)let y++;;3)let x++;;esac
let x%=$c;let y%=$L;ct;[ "$y$x" == "$j$i" ]&&{ let le++;A;let S++;}
l=`tr -dc ' '<<<"$t"|wc -c`;gt;[ $l -gt $le ]&&mt;}
ky() { k=$1;read -sN1 -t 0.01 k1;read -sN1 -t 0.01 k2;read -sN1 -t 0.01 k3
k+=${k1}${k2}${k3};case $k in w|$'\e[A'|$'\e0A')d=0;;a|$'\e[D'|$'\e0D')d=1;;
s|$'\e[B'|$'\e0B')d=2;;d|$'\e[C'|$'\e0C')d=3;;esac;}
while :;do da ' ';G ' ';M;da "@";G "#";sc;read -s -n 1 -t 0.1 k && ky "$k";done
