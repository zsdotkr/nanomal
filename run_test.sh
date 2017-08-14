#!/bin/bash 

test_file() {
	org=$1
	file=$2

	org=`grep "\#\#" $org | awk -F "##" '{print $2}'`
	target=`./test -f $file | grep "\#\#" | awk -F "##" '{print $2}'`

	if [ "$org" != "$target" ]; then 
		echo "FAIL : $file"
		echo " ** ORG  : " $org
		echo " ** CALC : " $target
	else
		echo "PASS : $file"
	fi
}

case "$1" in 

check)
	target=`ls sample/*.txt`
	for name in $target
	do
		title=`echo $name | awk -F"." '{print $1}'`
	
		file1=$title.pcap
		file2=$title.pcapng
	
		if [ -f $file1 ]; then 
			test_file $name $file1
		elif [ -f $file2 ]; then 
			test_file $name $file2
		else
			echo "ERR  : Can't find $title"
		fi 
	done
	;;
gen)
	target=`ls sample/*.pcap*`
	for name in $target
	do
		title=`echo $name | awk -F"." '{print $1}'`
		dest=$title.txt
		./test -f $name > $dest
	done
	;;
*)
	echo "Usage $0 check | gen"
	;;
esac

