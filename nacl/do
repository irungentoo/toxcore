#!/bin/sh

# nacl/do
# D. J. Bernstein
# Public domain.

version=`cat version`
project=nacl
shorthostname=`hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]'`

top="`pwd`/build/$shorthostname"
bin="$top/bin"
lib="$top/lib"
include="$top/include"
work="$top/work"

PATH="/usr/local/bin:$PATH"
PATH="/usr/sfw/bin:$PATH"
PATH="$bin:$PATH"
export PATH

LD_LIBRARY_PATH="/usr/local/lib/sparcv9:/usr/local/lib:$LD_LIBRARY_PATH"
LD_LIBRARY_PATH="/usr/sfw/lib/sparcv9:/usr/sfw/lib:$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH

# and wacky MacOS X
DYLD_LIBRARY_PATH="/usr/local/lib/sparcv9:/usr/local/lib:$DYLD_LIBRARY_PATH"
DYLD_LIBRARY_PATH="/usr/sfw/lib/sparcv9:/usr/sfw/lib:$DYLD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH

# and work around bug in GNU sort
LANG=C
export LANG

rm -rf "$top"
mkdir -p "$top"
mkdir -p "$bin"
mkdir -p "$lib"
mkdir -p "$include"

exec >"$top/log"
exec 2>&1
exec 5>"$top/data"
exec </dev/null

echo "=== `date` === starting"

echo "=== `date` === hostname"
hostname || :
echo "=== `date` === uname -a"
uname -a || :
echo "=== `date` === uname -M"
uname -M || :
echo "=== `date` === uname -F"
uname -F || :
echo "=== `date` === /usr/sbin/lscfg | grep proc"
/usr/sbin/lscfg | grep proc || :
echo "=== `date` === /usr/sbin/lsattr -El proc0"
/usr/sbin/lsattr -El proc0 || :
echo "=== `date` === cat /proc/cpuinfo"
cat /proc/cpuinfo || :
echo "=== `date` === cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq || :
echo "=== `date` === cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq || :
echo "=== `date` === cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq || :
echo "=== `date` === cat /sys/devices/system/cpu/cpu0/clock_tick"
cat /sys/devices/system/cpu/cpu0/clock_tick || :
echo "=== `date` === sysctl hw.model"
sysctl hw.model || :
echo "=== `date` === sysctl machdep.tsc_freq"
sysctl machdep.tsc_freq || :
echo "=== `date` === /usr/sbin/psrinfo -v"
/usr/sbin/psrinfo -v || :

echo "=== `date` === building okcompilers"
rm -rf "$work"
mkdir -p "$work"
cp -pr okcompilers/* "$work"
( cd "$work" && sh do )
cp -p "$work"/bin/* "$bin"

echo "=== `date` === building cpuid"
rm -rf "$work"
mkdir -p "$work"
cp -pr cpuid/* "$work"
( cd "$work" && sh do )
cp -pr "$work"/include/* "$include"

echo "=== `date` === building inttypes"
rm -rf "$work"
mkdir -p "$work"
cp -pr inttypes/* "$work"
( cd "$work" && sh do )
cp -pr "$work"/include/* "$include"

echo "=== `date` === building cpucycles"
rm -rf "$work"
mkdir -p "$work"
cp -pr cpucycles/* "$work"
( cd "$work" && sh do )
cp -pr "$work"/lib/* "$lib"
cp -pr "$work"/include/* "$include"

echo "=== `date` === building randombytes"
rm -rf "$work"
mkdir -p "$work"
cp -pr randombytes/* "$work"
( cd "$work" && sh do )
cp -pr "$work"/lib/* "$lib"
cp -pr "$work"/include/* "$include"

okabi \
| while read abi
do
  rm -rf "$work"
  mkdir -p "$work"
  echo 'void crypto_'"$project"'_base(void) { ; }' > "$work/${project}_base.c"
  okc-$abi \
  | while read compiler
  do
    ( cd "$work" && $compiler -c ${project}_base.c ) && break
  done
  okar-$abi cr "$lib/$abi/lib${project}.a" "$work/${project}_base.o"
  ( ranlib "$lib/$abi/lib${project}.a" || exit 0 )
done

# loop over operations
cat OPERATIONS \
| while read o
do
  [ -d "$o" ] || continue

  selected=''
  [ -f "$o/selected" ] && selected=`cat "$o/selected"`

  # for each operation, loop over primitives
  ls "$o" \
  | sort \
  | while read p
  do
    [ -d "$o/$p" ] || continue
    expectedchecksum=''
    [ -f "$o/$p/checksum" ] && expectedchecksum=`cat "$o/$p/checksum"`
    op="${o}_${p}"

    startdate=`date +%Y%m%d`

    # for each operation primitive, loop over abis
    okabi \
    | while read abi
    do
      echo "=== `date` === $abi $o/$p"
      libs=`"oklibs-$abi"`
      libs="$lib/$abi/cpucycles.o $libs"
      [ -f "$lib/$abi/lib${project}.a" ] && libs="$lib/$abi/lib${project}.a $libs"

      rm -rf "$work"
      mkdir -p "$work"
      mkdir -p "$work/best"

      # for each operation primitive abi, loop over implementations
      find "$o/$p" -follow -name "api.h" \
      | sort \
      | while read doth
      do
        implementationdir=`dirname $doth`
	opi=`echo "$implementationdir" | tr ./- ___`

	echo "=== `date` === $abi $implementationdir"

	rm -rf "$work/compile"
	mkdir -p "$work/compile"
  
	cfiles=`ls "$implementationdir" | grep '\.c$' || :`
	sfiles=`ls "$implementationdir" | grep '\.[sS]$' || :`
	cppfiles=`ls "$o" | grep '\.cpp$' || :`
  
	cp -p "$o"/*.c "$work/compile/"
	cp -p "$o"/*.cpp "$work/compile/"

	cp -pr "$implementationdir"/* "$work/compile"

	cp -p "try-anything.c" "$work/compile/try-anything.c"
	cp -p "measure-anything.c" "$work/compile/measure-anything.c"

	cp -p MACROS "$work/compile/MACROS"
	cp -p PROTOTYPES.c "$work/compile/PROTOTYPES.c"
	cp -p PROTOTYPES.cpp "$work/compile/PROTOTYPES.cpp"

	(
	  cd "$work/compile"
	  (
	    echo "#ifndef ${o}_H"
	    echo "#define ${o}_H"
	    echo ""
	    echo "#include \"${op}.h\""
	    echo ""
	    egrep "${o}"'$|'"${o}"'\(|'"${o}"'_' < MACROS \
	    | sed "s/$o/$op/" | while read mop
	    do
	      echo "#define ${mop} ${mop}" | sed "s/$op/$o/"
	    done
	    echo "#define ${o}_PRIMITIVE \"${p}\""
	    echo "#define ${o}_IMPLEMENTATION ${op}_IMPLEMENTATION"
	    echo "#define ${o}_VERSION ${op}_VERSION"
	    echo ""
	    echo "#endif"
	  ) > "$o.h"
	  (
	    echo "#ifndef ${op}_H"
	    echo "#define ${op}_H"
	    echo ""
	    sed 's/[ 	]CRYPTO_/ '"${opi}"'_/g' < api.h
	    echo '#ifdef __cplusplus'
	    echo '#include <string>'
	    egrep "${o}"'$|'"${o}"'\(|'"${o}"'_' < PROTOTYPES.cpp \
	    | sed "s/$o/$opi/"
	    echo 'extern "C" {'
	    echo '#endif'
	    egrep "${o}"'$|'"${o}"'\(|'"${o}"'_' < PROTOTYPES.c \
	    | sed "s/$o/$opi/"
	    echo '#ifdef __cplusplus'
	    echo '}'
	    echo '#endif'
	    echo ""
	    egrep "${o}"'$|'"${o}"'\(|'"${o}"'_' < MACROS \
	    | sed "s/$o/$opi/" | while read mopi
	    do
	      echo "#define ${mopi} ${mopi}" | sed "s/$opi/$op/"
	    done
	    echo "#define ${op}_IMPLEMENTATION \"${implementationdir}\""
	    echo "#ifndef ${opi}_VERSION"
	    echo "#define ${opi}_VERSION \"-\""
	    echo "#endif"
	    echo "#define ${op}_VERSION ${opi}_VERSION"
	    echo ""
	    echo "#endif"
	  ) > "$op.h"

	  okc-$abi \
	  | while read compiler
	  do
	    echo "=== `date` === $abi $implementationdir $compiler"
	    compilerword=`echo "$compiler" | tr ' ' '_'`
	    ok=1
	    for f in $cfiles $sfiles
	    do
	      if [ "$ok" = 1 ]
	      then
		$compiler \
		  -I. -I"$include" -I"$include/$abi" \
		  -c "$f" >../errors 2>&1 || ok=0
		( if [ `wc -l < ../errors` -lt 25 ]
		  then
		    cat ../errors
		  else
		    head ../errors
		    echo ...
		    tail ../errors
		  fi
		) \
		| while read err
		do
		  echo "$version $shorthostname $abi $startdate $o $p fromcompiler $implementationdir $compilerword $f $err" >&5
		done
	      fi
	    done

	    [ "$ok" = 1 ] || continue
	    okar-$abi cr "$op.a" *.o || continue
	    ranlib "$op.a"

	    $compiler \
	      -I. -I"$include" -I"$include/$abi" \
	      -o try try.c try-anything.c \
	      "$op.a" $libs >../errors 2>&1 || ok=0
	    cat ../errors \
	    | while read err
	    do
	      echo "$version $shorthostname $abi $startdate $o $p fromcompiler $implementationdir $compilerword try.c $err" >&5
	    done
	    [ "$ok" = 1 ] || continue

	    if sh -c './try || exit $?' >../outputs 2>../errors
	    then
	      checksum=`awk '{print $1}' < ../outputs`
	      cycles=`awk '{print $2}' < ../outputs`
	      checksumcycles=`awk '{print $3}' < ../outputs`
	      cyclespersecond=`awk '{print $4}' < ../outputs`
	      impl=`awk '{print $5}' < ../outputs`
	    else
	      echo "$version $shorthostname $abi $startdate $o $p tryfails $implementationdir $compilerword error $?" >&5
	      cat ../outputs ../errors \
	      | while read err
	      do
	        echo "$version $shorthostname $abi $startdate $o $p tryfails $implementationdir $compilerword $err" >&5
	      done
	      continue
	    fi

	    checksumok=fails
	    [ "x$expectedchecksum" = "x$checksum" ] && checksumok=ok
	    [ "x$expectedchecksum" = "x" ] && checksumok=unknown
	    echo "$version $shorthostname $abi $startdate $o $p try $checksum $checksumok $cycles $checksumcycles $cyclespersecond $impl $compilerword" >&5
	    [ "$checksumok" = fails ] && continue

	    [ -s ../bestmedian ] && [ `cat ../bestmedian` -le $cycles ] && continue
	    echo "$cycles" > ../bestmedian

	    $compiler -D'COMPILER="'"$compiler"'"' \
	      -DLOOPS=1 \
	      -I. -I"$include" -I"$include/$abi" \
	      -o measure measure.c measure-anything.c \
	      "$op.a" $libs >../errors 2>&1 || ok=0
	    cat ../errors \
	    | while read err
	    do
	      echo "$version $shorthostname $abi $startdate $o $p fromcompiler $implementationdir $compilerword measure.c $err" >&5
	    done
	    [ "$ok" = 1 ] || continue

	    for f in $cppfiles
	    do
	      okcpp-$abi \
	      | while read cppcompiler
	      do
	        echo "=== `date` === $abi $implementationdir $cppcompiler"
	        $cppcompiler \
		  -I. -I"$include" -I"$include/$abi" \
		  -c "$f" && break
	      done
	    done

	    rm -f ../best/*.o ../best/measure || continue
	    for f in *.o
	    do
	      cp -p "$f" "../best/${opi}-$f"
	    done
	    cp -p "$op.h" "../$op.h"
	    cp -p "$o.h" "../$o.h"
	    cp -p measure ../best/measure
	  done
	)
      done

      echo "=== `date` === $abi $o/$p measuring"

      "$work/best/measure" \
      | while read measurement
      do
	echo "$version $shorthostname $abi $startdate $o $p $measurement" >&5
      done

      [ -f "$o/$p/used" ] \
      && okar-$abi cr "$lib/$abi/lib${project}.a" "$work/best"/*.o \
      && ( ranlib "$lib/$abi/lib${project}.a" || exit 0 ) \
      && cp -p "$work/$op.h" "$include/$abi/$op.h" \
      && [ -f "$o/$p/selected" ] \
      && cp -p "$work/$o.h" "$include/$abi/$o.h" \
      || :
    done
  done
done

for language in c cpp
do
  for bintype in commandline tests
  do
    ls $bintype \
    | sed -n 's/\.'$language'$//p' \
    | sort \
    | while read cmd
    do
      echo "=== `date` === starting $bintype/$cmd"
    
      rm -rf "$work"
      mkdir -p "$work/compile"
    
      cp "$bintype/$cmd.$language" "$work/compile/$cmd.$language"
      [ "$bintype" = tests ] && cp -p "$bintype/$cmd.out" "$work/compile/$cmd.out"
    
      okabi \
      | while read abi
      do
        [ -x "$bin/$cmd" ] && break
    
        libs=`"oklibs-$abi"`
        libs="$lib/$abi/cpucycles.o $libs"
        libs="$libs $lib/$abi/randombytes.o"
    
        ok${language}-$abi \
        | while read compiler
        do
          [ -x "$bin/$cmd" ] && break
    
          echo "=== `date` === $bintype/$cmd $abi $compiler"
          (
            cd "$work/compile"
            if $compiler \
              -I"$include" -I"$include/$abi" \
              -o "$cmd" "$cmd.${language}" \
              "$lib/$abi/lib${project}.a" $libs
	    then
	      case "$bintype" in
	        commandline) cp -p "$cmd" "$bin/$cmd" ;;
		tests) "./$cmd" | cmp - "$cmd.out" || "./$cmd" ;;
	      esac
	    fi
          )
        done
      done
    done
  done
done

echo "=== `date` === starting curvecp"

okabi \
| awk '
  { if ($1=="amd64" || $1=="ia64" || $1=="ppc64" || $1=="sparcv9" || $1=="mips64") print 1,$1
    else if ($1 == "mips32") print 2,$1
    else print 3,$1
  }
' \
| sort \
| while read okabipriority abi
do
  [ -x "$bin/curvecpmessage" ] && break
  libs=`"oklibs-$abi"`
  libs="$lib/$abi/cpucycles.o $libs"
  libs="$libs $lib/$abi/randombytes.o"

  okc-$abi \
  | while read compiler
  do
    [ -x "$bin/curvecpmessage" ] && break

    echo "=== `date` === curvecp $abi $compiler"
    rm -rf "$work"
    mkdir -p "$work/compile"
    cp curvecp/* "$work/compile"
    (
      cd "$work/compile"
      cat SOURCES \
      | while read x
      do
        $compiler -I"$include" -I"$include/$abi" -c "$x.c"
      done

      if okar-$abi cr curvecplibs.a `cat LIBS`
      then
        cat TARGETS \
	| while read x
	do
	  $compiler -I"$include" -I"$include/$abi" \
	  -o "$x" "$x.o" \
	  curvecplibs.a "$lib/$abi/lib${project}.a" $libs \
	  && cp -p "$x" "$bin/$x"
	done
      fi
    )
  done

done

echo "=== `date` === finishing"
