# Resources
## PCAP
* https://marcellelee.medium.com/ctf-challenge-walkthrough-network-traffic-analysis-12-challenges-in-one-pcap-bd8f01bcd0b6
* https://infosecwriteups.com/escaperoom-pcap-analysis-with-wireshark-ea7abcc68a18
* https://infoinsecu.wordpress.com/2019/07/28/network6-file-transfer-protocol/
* https://shankaraman.wordpress.com/tag/how-to-extract-ftp-files-from-wireshark-packet/
### PDF
* https://www.kali.org/tools/pdfcrack/
* https://blog.pentesteracademy.com/cracking-password-of-a-protected-pdf-file-using-hashcat-and-john-the-ripper-1b50074eeabd
* https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
* https://www.kali.org/tools/john/#pdf2john
* john from scratch https://ourcodeworld.com/articles/read/939/how-to-crack-a-pdf-password-with-brute-force-using-john-the-ripper-in-kali-linux
* no output from john so : https://security.stackexchange.com/questions/183554/why-wont-pdf2john-extract-the-password-hash-of-this-encrypted-pdf-getting-blan
* forensics: https://trailofbits.github.io/ctf/forensics/
* http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf
* pdf dna -> https://github.com/corkami/docs/blob/master/PDF/PDF.md
* qpdf -> https://github.com/qpdf/qpdf
* how to crack pdf vol III https://blog.didierstevens.com/2017/12/26/cracking-encrypted-pdfs-part-1/
* some pdf tools https://blog.didierstevens.com/programs/pdf-tools/

#Story 

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
