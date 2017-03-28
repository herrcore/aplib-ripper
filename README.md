# aplib-ripper
Use this library to automatically extract PE files compressed with aplib from a binary blob. 

## What is aPlib?
Aplib is a lightweight LZ-based [compression library](http://ibsensoftware.com/products_aPLib.html) that is commonly used in packers and shell code. It is easy to spot a PE file that has been compressed using aPlib because the PE magic bytes MZ become **M8Z**.

The aplib-ripper (**aprip.py**) simply automates the process of locating those magic bytes in a file an attempting to decompress the resulting data into a PE file.

Let's get automating!

![](https://media.giphy.com/media/CGS2MNrIDLpVm/giphy.gif)

## Use Cases
Aplib-ripper (**aprip.py**) can be imported as a module and used in your python tooling or it can used as a standalone CLI tool. 

### aprip module 
To use aprip.py as a module you simply need to import it and use the **extract_all** function to automatically extract all aplib compressed PE files from you data blob. 
```
>>> import aprip
>>> #Extract PE files from data 
>>> #pe_files is a list containing all extracted PE files
>>> pe_files = aprip.extract_all(data)
>>>
```

#### aprip function reference 
**_find_candidates(blob)_**<br>
&nbsp;&nbsp;&nbsp;&nbsp;Find potential aplib candidates.<br>
&nbsp;&nbsp;&nbsp;&nbsp;**Args:**<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;blob (string): binary string of the blob to search<br>
&nbsp;&nbsp;&nbsp;&nbsp;**Returns:**<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;list: offsets to each of the candidates (empty if none found)
    
**_extract_candidate(blob, offset)_**<br>
&nbsp;&nbsp;&nbsp;&nbsp;Attempt to decrypt candidate and test DOS header.<br>
&nbsp;&nbsp;&nbsp;&nbsp;**Args:**<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;blob (string): binary string of the blob to search<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;offset (int): offset in the blob (candidate start)<br>
&nbsp;&nbsp;&nbsp;&nbsp;**Returns:**<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;string: extracted PE file (none if no PE is extracted)<br>

**_extract_all(blob)_**<br>
&nbsp;&nbsp;&nbsp;&nbsp;Locate potential aplib candidates and attempt to decrypt them.<br>
&nbsp;&nbsp;&nbsp;&nbsp;**Args:**<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;blob (string): binary string of the blob to search<br>
&nbsp;&nbsp;&nbsp;&nbsp;**Returns:**<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;list: list of PE files that have been extracted (empty if none are found)<br>

### aprip CLI
To use aprip.py as a tool from the command line you simply need to pass it the name of the file that you will be extracting the aPlib compressed PE files from. Each extracted file will be written to a file “dump0.bin”, “dump1.bin”, …

```
$aprip test.bin 

-----------------------------

  APLIB RIPPER 1.1

-----------------------------

Ripping PE files, this may take some time...
 - Ripped PE writing to file: dump0.bin
 - Ripped PE writing to file: dump1.bin
```
## Acknowledgments
A big thank you to the creator of the aplib python module: Kabopan http://code.google.com/p/kabopan/

## Feedback / Help
* Any questions, comments, requests hit me up on twitter: @herrcore 
* Pull requests welcome!
