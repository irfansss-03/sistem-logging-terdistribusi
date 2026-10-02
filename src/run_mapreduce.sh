#!/bin/bash
#DATE=$(date +%s)
#INPUT="/user/logs/logs.txt"
#OUTPUT="/user/logs/output_$DATE"

#hdfs dfs -put -f logs.txt /user/logs/logs.txt

#hadoop jar /home/sirpann/Downloads/hadoop/share/hadoop/tools/lib/hadoop-streaming-*.jar \
#  -file mapper.py -mapper mapper.py \
#  -file reducer.py -reducer reducer.py \
#  -input $INPUT -output $OUTPUT

#hdfs dfs -cat $OUTPUT/part-00000 > hasil.txt

#rm -f *.txt

#!/bin/bash
DATE=$(date +%s)
INPUT="/user/logs/logs.txt"
OUTPUT="/user/logs/output_$DATE"

# 1️⃣ Pastikan folder di HDFS ada
hdfs dfs -mkdir -p /user/logs

# 2️⃣ Upload logs.txt ke HDFS
hdfs dfs -put -f logs.txt $INPUT
#hdfs dfs -put -f logs.txt /user/logs/logs.txt

# 3️⃣ Jalankan MapReduce
hadoop jar /home/sirpann/Downloads/hadoop/share/hadoop/tools/lib/hadoop-streaming-*.jar \
  -file mapper.py -mapper mapper.py \
  -file reducer.py -reducer reducer.py \
  -input $INPUT -output $OUTPUT

# 4️⃣ Simpan hasil ke lokal
hdfs dfs -cat $OUTPUT/part-00000 > hasil.txt
