# Blind-SQLi-Tool
auto_SQLi, an automatic blind SQLi Tool that dumps tables from POST or GET requests.

## Usage:
1. Copy a request from a webpage that you try the BSQLi on. (Check examples for how it should look)
2. Save the request to a file (This file will be used by the tool)
3. run `python3 auto_SQLi.py <request file> <common tables wordlist> <common columns wordlist>`
4. See results in the output file `table.txt`.
  * If you want to cahnge the output file name run with `-o, --output`, followed by the output file name of your choice.
  
## Script Work Flow:
1. Setting the string of the differnet outputs that the webpage responds with. Such as: "database error", "Wrong password", "login successfull"
2. Defines the method that the request uses (POST or GET)
3. Trying different injection brackets until a successfull found.
4. Union Automation.
5. Guessing table name from word list.
6. Guessing column names from word list.
7. Guessing number of rows in the table.
8. Fetches all data in columns and rows (Brute Force)
9. Creating data frame to output as a formmated table, prints table and saves to the output file.

## Requirements:
* bs4
* Python 3
* Burpee
* urllib.parse
* argparse
