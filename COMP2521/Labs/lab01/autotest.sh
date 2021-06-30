#!/bin/bash
Fun1(){
    for t in $( seq 1 10 );
    do
        echo -n "第$t次测试：你的程序"
        (time ./useIntList < /tmp/$USER.nums > /dev/null) 2>&1
    done
}
Fun2(){
    for t in $( seq 1 10 );
    do
        echo -n "第$t次测试：sort命令"
        (time sort -n < /tmp/$USER.nums > /dev/null) 2>&1
    done
}
num=("10000" "20000")
mess=("重复的随机顺序" "重复的有序数列" "重复的反序数列" "不重复的有序数列" "不重复的反序数列"  "不重复的随机数列")
for size in ${num[@]};
do
    echo "size:" $size
    com=("./randList $size" "sort -n /tmp/$USER.nums" "sort -nr /tmp/$USER.nums" "seq $size")
    for i in $( seq 0 3 );
    do
        ${com[$i]}> /tmp/$USER.nums
        echo ${mess[$i]}"完成"
        if [ ! -d "out" ]
        then
            mkdir "out"
        fi
        Fun1 > ./out/$size${mess[$i]}"_your".out
        Fun2 > ./out/$size${mess[$i]}"_sort".out
    done
    seq ${size} | sort -nr > /tmp/$USER.nums #不重复的反序数列
    echo "${mess[4]}完成"
    Fun1 > ./out/$size${mess[4]}"_your".out
    Fun2 > ./out/$size${mess[4]}"_sort".out
    seq ${size} | sort -R > /tmp/$USER.nums #不重复的随机数列
    echo "${mess[5]}完成"
    Fun1 > ./out/$size${mess[5]}"_your".out
    Fun2 > ./out/$size${mess[5]}"_sort".out
done
