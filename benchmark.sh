#!/bin/bash

rm -f encryptSecuencial encryptParalelo

g++ encrypt.cpp -o encryptSecuencial -lssl -lcrypto
if [ $? -ne 0 ]; then
    echo "Error: No se pudo compilar el programa secuencial"
    exit 1
fi

g++ encryptParalelo.cpp -o encryptParalelo -lssl -lcrypto -lpthread  
if [ $? -ne 0 ]; then
    echo "Error: No se pudo compilar el programa paralelo"
    exit 1
fi

CSV="resultados.csv"
N=3

if [ ! -f "$CSV" ]; then
    echo "Tipo,Num_Hilos,Iteracion,Tiempo" > $CSV
fi

echo "Encriptacion secuencial"
for ((i=1; i<=N; i++))
do
    inicio=$(date +%s.%N)
    ./secuencial > /dev/null 2>&1
    fin=$(date +%s.%N)
    tiempo=$(echo "$fin - $inicio" | bc)
    echo "Secuencial,1,$i,$tiempo" >> $CSV
    echo "  Iteración $i: $tiempo s"
done

echo "Encriptacion paralela"
for h in 1 2 4 8
do
    for ((i=1; i<=N; i++))
    do
        inicio=$(date +%s.%N)
        echo -e "1\n$h" | ./paralelo > /dev/null 2>&1
        fin=$(date +%s.%N)
        tiempo=$(echo "$fin - $inicio" | bc)
        echo "Paralelo,$h,$i,$tiempo" >> $CSV
        echo "  Hilos=$h Iteración $i: $tiempo s"
    done
done

echo "Resultados en $CSV"