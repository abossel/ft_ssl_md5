file1=md5_test_1.txt
file2=md5_test_2.txt
random=md5_random.txt

if [ -f "../ft_ssl" ]
then
    echo "Found ft_ssl"
else
    echo "Missing ft_ssl"
    exit
fi

gcc randstr.c -o randstr

rm "$file1" "$file2" 2>/dev/null

for i in $(seq 0 1000)
do
    echo Testing $i random character string
    str=$(./randstr $i)
    #md5 -s "$str" >> "$file1"
    printf "$str" | md5sum | tr -d " -" >> "$file1"
    ../ft_ssl md5 -q -s "$str" >> "$file2"
done

for i in $(seq 1001 2000)
do
    echo Testing $i byte random character file
    head -c $i < /dev/random > "$random"
    #md5 -q "$random" >> "$file1"
    cat "$random" | md5sum | tr -d " -" >> "$file1"
    ../ft_ssl md5 -q "$random" >> "$file2"
done

diff -s "$file1" "$file2"

rm "$file1" "$file2" "$random" randstr
