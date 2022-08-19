#!/bin/bash

cd build/reports/jacoco/test/html/

row=`cat index.html | grep -o '<td>Total<\/td>.*<td class="ctr2">[0-9][0-9]%<\/td>'`

percent=`echo $row | grep -o -m2 '[0-9][0-9]%' | tail -n1`

echo $percent
