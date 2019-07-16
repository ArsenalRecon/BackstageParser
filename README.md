## Backstage Parser ##

Arsenal's Backstage Parser is a python tool that can be used to parse the contents of Microsoft Office files found in the “\Users\(User)\AppData\Local\Microsoft\Office\16.0\BackstageinAppNavCache” path.

David Cowen from C-G Partners blogged in October 2018 (http://www.learndfir.com/2018/10/18/daily-blog-510-office-2016-backstage-artifacts/) about interesting information left behind by the use of Microsoft Office’s “Backstage” view. Arsenal’s Brian Gerdon found the Backstage references to both local and remote folder paths, which were no longer available, particularly interesting. According to Microsoft (https://support.office.com/en-us/article/start-backstage-with-the-file-tab-04610088-406c-43d0-98a0-c1999ab4ef53), "When you start a Microsoft Office program, or after you click the File tab, you can see the Microsoft Office Backstage view. If you need to create a new file, open an existing file, print, save , change options or more, Backstage is the place to do it. In short, it is everything that you do to a file that you don't do in the file.”

## Usage ##
Run with python (3): 

Against a single file -f INPUTFILE

Against all files in a directory (recursively) -d INPUTDIRECTORY

Output as CSV (-oc), TSV (-ot), PSV (-op), or JSON (-oj)

Write output to file -o OUTPUTFILE

Examples

python3 BackstageParser.py -f INPUTFILE -ot -o outputfile.tsv

or

python3 BackstageParser.py -d INPUTDIRECTORY -op -o outputfile.psv


## Contributions ##

Contributions and improvements to the code are welcomed.

## License ##

Distributed under the MIT License. See License.md for details.

## More Information ##

To learn more about Arsenal’s digital forensics software and training, please visit https://ArsenalRecon.com and follow us on Twitter @ArsenalRecon (https://twitter.com/ArsenalRecon).

To learn more about Arsenal’s digital forensics consulting services, please visit https://ArsenalExperts.com and follow us on Twitter @ArsenalArmed (https://twitter.com/ArsenalArmed).
