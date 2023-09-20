# Resources
## PCAP
* https://marcellelee.medium.com/ctf-challenge-walkthrough-network-traffic-analysis-12-challenges-in-one-pcap-bd8f01bcd0b6
* https://infosecwriteups.com/escaperoom-pcap-analysis-with-wireshark-ea7abcc68a18
* https://infoinsecu.wordpress.com/2019/07/28/network6-file-transfer-protocol/
* https://shankaraman.wordpress.com/tag/how-to-extract-ftp-files-from-wireshark-packet/

# Story & Solution
* pcapng file has been scanned - Statistics -> Protocol Hierarchy -> Saw FTP and some UDP
* Filter by FTP
* Right clicked on an FTP package, Follow->TCP Stream
* Saw `220 Oops ! Something went wrong! Error Message: TVktVjNyWV81M0N1UjNfRnRQX0YxbDMtUDRTcw`, suspected that `TVktVjNyWV81M0N1UjNfRnRQX0YxbDMtUDRTcw` message is base64 encoded
* decoded with echo `'TVktVjNyWV81M0N1UjNfRnRQX0YxbDMtUDRTcw' |base64 --decode` and resulted `MY-V3rY_53CuR3_FtP_F1l3-P4S` but it has a missing char.
* So tried `'TVktVjNyWV81M0N1UjNfRnRQX0YxbDMtUDRTcw==' |base64 --decode` and voala! `MY-V3rY_53CuR3_FtP_F1l3-P4Ss` is exposed
* Guess we need more data went through FTP and filter by `ftp-data` on Wireshark. Saw one file transaction. 
* Followed TCP stream and set to Show and Save data as `Raw`. Saved as -> `found_ftp_data.pdf`
* Then open pdf file, using previously found password : `MY-V3rY_53CuR3_FtP_F1l3-P4Ss`
* The flag is in front of us! `STMCTF{4r3_Y0u_N3tW0rK_M4sT3R?}`
