* pcapng file has been scanned - Statistics -> Protocol Hierarchy -> Saw FTP and some UDP
* Found MY-V3rY_53CuR3_FtP_F1l3-P4Ss from one of FTP request
* Found a file that transferred from FTP server which is a encrypted PDF
* Found out that PDF didn't encrypted with a standard encryption
* Used pdf2john.pe to get hash but it didn't give a hash
* perl /Users/covayurt/Documents/CTF/Tools/JohnTheRipper/run/pdf2john.pl /Users/covayurt/Documents/CTF/STM/2022/network_forensic/ftp/tcp_file.pdf
* pdf_parser extracted some valuable information
* python3 ../../../../Tools/pdf-parser.py -s /Encrypt tcp_file.pdf
   trailer
  <<
    /Info 18 0 R
    /Encrypt 17 0 R
    /ID [<e297567983604560f58c3307b3a01904><553168baccd65d38f0860a1d81f32792>]
    /Root 1 0 R
    /Size 19
  >>
* and then python3 ../../../../Tools/pdf-parser.py -o 17 tcp_file.pdf
  obj 17 0
 Type:
 Referencing:

  <<
    /O '(.....%..q!O...+...n{\\\\$E\\f..1:..U.)'
    /P -3904
    /CF
      <<
        /StdCF
          <<
            /AuthEvent /DocOpen
            /Length 16
            /CFM /AESV2
          >>
      >>
    /R 4
    /StmF /StdCF
    /Filter /Standard
    /U '(eN=.\\nR.....H..x.................)'
    /V 4
    /StrF /StdCF
    /Length 128
  >>
* 