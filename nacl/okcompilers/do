#!/bin/sh -e

mkdir oldbin
mkdir bin

for language in c cpp
do
  exec <$language
  exec 9>${language}-works
  
  while read c options
  do
    echo "=== `date` === checking $c $options" >&2
    rm -f test*
    (
      echo "#!/bin/sh"
      echo 'PATH="'"$PATH"'"'
      echo 'export PATH'
      echo "$c" "$options" '"$@"'
    ) > test-okc
    chmod 755 test-okc
    cat lib.c main.c > test.$language || continue
    ./test-okc -o test test.$language || continue
    ./test || continue
    cp main.c test1.$language || continue
    cp lib.c test2.$language || continue
    ./test-okc -c test1.$language || continue
    ./test-okc -c test2.$language || continue
    ./test-okc -o test1 test1.o test2.o || continue
    ./test1 || continue
    echo "=== `date` === success: $c $options is ok"
    echo "$c $options" >&9
  done

  mv ${language}-works $language
done

exec <c

exec 7>oldbin/okabi
chmod 755 oldbin/okabi
echo "#!/bin/sh" >&7

while :
do
  exec <c
  read c options || break

  for language in c cpp
  do
    exec 8>${language}-compatible
    exec 9>${language}-incompatible
    echo "=== `date` === checking compatibility with $c $options" >&2
    exec <$language
    while read c2 options2
    do
      echo "=== `date` === checking $c2 $options2" >&2
      works=1
      rm -f test*
      (
        echo "#!/bin/sh"
        echo 'PATH="'"$PATH"'"'
        echo 'export PATH'
        echo "$c" "$options" '"$@"'
      ) > test-okc
      chmod 755 test-okc
      (
        echo "#!/bin/sh"
        echo 'PATH="'"$PATH"'"'
        echo 'export PATH'
        echo "$c2" "$options2" '"$@"'
      ) > test-okc2
      chmod 755 test-okc2
      if cp main.c test5.c \
      && cp main.cpp test5.cpp \
      && cp lib.c test6.c \
      && ./test-okc2 -c test5.$language \
      && ./test-okc -c test6.c \
      && ./test-okc2 -o test5 test5.o test6.o \
      && ./test5
      then
        echo "=== `date` === success: $c2 $options2 is compatible" >&2
        echo "$c2 $options2" >&8
      else
        echo "$c2 $options2" >&9
      fi
    done
  done

  abi=`awk '{print length($0),$0}' < c-compatible \
  | sort -n | head -1 | sed 's/ *$//' | sed 's/^[^ ]* //' | tr ' /' '__'`

  echo "echo '"$abi"'" >&7

  syslibs=""
  for i in -lm -lnsl -lsocket -lrt
  do
    echo "=== `date` === checking $i" >&2
    (
      echo "#!/bin/sh"
      echo 'PATH="'"$PATH"'"'
      echo 'export PATH'
      echo "$c" "$options" '"$@"' "$i" "$syslibs"
    ) > test-okclink
    chmod 755 test-okclink
    cat lib.c main.c > test.c || continue
    ./test-okclink -o test test.c $i $syslibs || continue
    ./test || continue
    syslibs="$i $syslibs"
    (
      echo '#!/bin/sh'
      echo 'echo "'"$syslibs"'"'
    ) > "oldbin/oklibs-$abi"
    chmod 755 "oldbin/oklibs-$abi"
  done

  foundokar=0
  exec <archivers
  while read a
  do
    echo "=== `date` === checking archiver $a" >&2
    (
      echo "#!/bin/sh"
      echo 'PATH="'"$PATH"'"'
      echo 'export PATH'
      echo "$a" '"$@"'
    ) > test-okar
    chmod 755 test-okar
    cp main.c test9.c || continue
    cp lib.c test10.c || continue
    ./test-okc -c test10.c || continue
    ./test-okar cr test10.a test10.o || continue
    ranlib test10.a || echo "=== `date` === no ranlib; continuing anyway" >&2
    ./test-okc -o test9 test9.c test10.a || continue
    ./test9 || continue
    cp -p test-okar "oldbin/okar-$abi"
    echo "=== `date` === success: archiver $a is ok" >&2
    foundokar=1
    break
  done

  case $foundokar in
    0)
      echo "=== `date` === giving up; no archivers work" >&2
      exit 111
    ;;
  esac

  for language in c cpp
  do
    mv ${language}-incompatible ${language}
    exec <${language}-compatible
    exec 9>"oldbin/ok${language}-$abi"
    chmod 755 "oldbin/ok${language}-$abi"
  
    echo "#!/bin/sh" >&9
    while read c2 options2
    do
      echo "echo '"$c2 $options2"'" >&9
    done
  done
done

exec 7>/dev/null

oldbin/okabi \
| while read abi
do
  oldbin/okc-$abi \
  | head -1 \
  | while read c
  do
    $c -o abiname abiname.c \
    && ./abiname "$abi"
  done
done > abinames

numabinames=`awk '{print $2}' < abinames | sort -u | wc -l`
numabis=`oldbin/okabi | wc -l`
if [ "$numabis" = "$numabinames" ]
then
  exec <abinames
  exec 7>bin/okabi
  chmod 755 bin/okabi
  echo '#!/bin/sh' >&7
  while read oldabi newabi
  do
    mv "oldbin/okc-$oldabi" "bin/okc-$newabi"
    mv "oldbin/okcpp-$oldabi" "bin/okcpp-$newabi"
    mv "oldbin/okar-$oldabi" "bin/okar-$newabi"
    mv "oldbin/oklibs-$oldabi" "bin/oklibs-$newabi"
    echo "echo $newabi" >&7
  done
else
  cp -p oldbin/* bin
fi
