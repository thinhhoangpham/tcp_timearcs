# TCP TimeArcs: Temporal Visualization of Attack Patterns in Large-Scale Network Traffic

## Academic Paper Introduction (Draft)

---

## 1. Introduction

Network security analysis faces a critical challenge: how to effectively visualize and understand temporal attack patterns in massive-scale network traffic captures. Modern network infrastructures generate terabytes of packet data daily, with individual network capture (PCAP) files frequently exceeding 60 gigabytes [1]. While traditional network analysis tools provide detailed packet-level inspection capabilities, they struggle to reveal the temporal dynamics and multi-host coordination patterns characteristic of contemporary cyber attacks [2, 3].

### 1.1 The Scalability Problem

Conventional network traffic analysis tools, particularly Wireshark—the de facto standard for packet analysis—face severe scalability limitations when processing large PCAP files. Wireshark cannot efficiently analyze gigabyte-scale datasets and frequently crashes with out-of-memory errors, particularly when analyzing stateful protocols like TCP [4]. These limitations are not merely technical inconveniences; they represent fundamental barriers to understanding modern attack campaigns that unfold across millions of packets over extended time periods [5].

Beyond memory constraints, PCAP files were never designed for managing packet captures larger than a few hundred megabytes. Reading, filtering, and searching operations become prohibitively slow and tedious beyond this threshold [6]. For security analysts investigating live incidents, where time is critical, this performance degradation can delay threat detection and response by hours or even days [7].

### 1.2 The Temporal Visualization Gap

Network intrusion detection systems (IDS) and traffic analysis platforms generate vast quantities of alert data, yet lack effective mechanisms for revealing temporal relationships between attack events [8]. While tools like Suricata and Snort excel at signature-based detection, they provide limited insight into *when* attack patterns emerge, *how* they evolve over time, and *which* IP addresses participate in coordinated attack campaigns [9, 10].

Recent research has emphasized the importance of temporal analysis for network security. Studies on network traffic classification demonstrate that while packet-level tools can retrieve basic information such as source IP addresses and ports, they fail to provide statistical insights into network session dynamics [11]. Similarly, research on interactive web-based visual analysis of network traffic highlights critical challenges in "handling complex network traffic data, manipulating various data attributes, incorporating different analytical approaches, and eventually identifying domain-specific insights from visual representations" [12].

### 1.3 Attack Pattern Discovery Challenges

Security analysts face a fundamental cognitive challenge: how to identify unknown attack patterns in datasets containing millions of packets exchanged between thousands of IP addresses. Traditional flow-graph visualizations display individual connections sequentially but cannot effectively show:

1. **Temporal bursts** indicating coordinated attack activity across multiple hosts
2. **Attack campaign evolution** spanning hours or days
3. **Multi-target coordination** where attackers simultaneously probe multiple victims
4. **Attack-phase transitions** from reconnaissance to exploitation to data exfiltration

These patterns are often visually imperceptible in packet lists or sequential flow diagrams, yet they represent critical forensic indicators for understanding attack methodology and attribution [13].

### 1.4 Our Contribution: TCP TimeArcs

We present **TCP TimeArcs**, a novel network traffic visualization tool that addresses these challenges by adapting the TimeArcs temporal relationship visualization technique [14] to the domain of network security analysis. TimeArcs was originally developed for visualizing dynamic relationships in text corpora and social networks, demonstrating the power of arc-based temporal diagrams for revealing fluctuations and clustering patterns over time.

TCP TimeArcs extends this approach to TCP/IP packet analysis with four key innovations:

**1. Scalable Browser-Based Architecture**
Through chunked data loading and streaming processing, TCP TimeArcs reduces memory consumption for a 60GB dataset from 10-20GB to approximately 200MB—a 50-100× reduction—enabling analysis of massive captures in standard web browsers without enterprise infrastructure [1].

**2. Temporal Magnification (Lensing)**
Inspired by the original TimeArcs focus+context technique [14], TCP TimeArcs implements interactive temporal magnification (2× to 200× zoom) that allows analysts to examine fine-grained timing details while maintaining awareness of overall attack campaign structure.

**3. Attack-Focused Visualization**
Arc diagrams intuitively reveal attack patterns through visual signatures: DDoS attacks appear as dense arc clusters, port scans manifest as sequential connection patterns, and coordinated multi-stage attacks display characteristic temporal progressions across multiple IP pairs.

**4. Progressive Data Loading**
A novel chunked file format (storing 200 flows per file) enables on-demand loading of detailed TCP flow information, reducing initial load times from minutes to seconds while maintaining instant access to flow-level forensic details.

### 1.5 Addressing the Scale-Detail Paradox

Network forensics requires both high-level pattern recognition and low-level packet inspection—what we term the "scale-detail paradox." Analysts must first identify *which* network activities warrant investigation among millions of packets, then drill down into *specific* TCP flows to understand attack mechanics. Traditional tools force analysts to choose: either visualize high-level statistics (losing temporal detail) or inspect individual packets (losing situational awareness).

TCP TimeArcs resolves this paradox through a two-stage workflow:

1. **Pattern Discovery Phase**: Analysts visualize attack patterns in aggregated data (25MB compressed from 60GB raw capture), selecting suspicious temporal arcs representing communication bursts between specific IP pairs during defined time windows.

2. **Detail Extraction Phase**: Selected IP pairs and time ranges trigger streaming extraction from the full dataset, generating filtered subsets (1-50MB) containing complete TCP flows with packet-level detail for forensic analysis.

This workflow enables analysts to visually identify attack signatures in massive datasets, then seamlessly transition to detailed flow-level investigation—combining the speed of statistical analysis with the forensic rigor of packet inspection.

### 1.6 Paper Organization

The remainder of this paper is organized as follows: Section 2 reviews related work in network traffic visualization and intrusion detection systems. Section 3 details the TCP TimeArcs architecture, including data processing pipeline, visualization techniques, and scalability mechanisms. Section 4 presents performance evaluation across datasets ranging from 10,000 to 1,000,000 packets. Section 5 demonstrates real-world applications through case studies of DDoS, port scanning, and multi-day attack campaigns. Section 6 discusses limitations and future research directions. Section 7 concludes.

---

## References

[1] TCP TimeArcs Project Documentation. "Memory-Efficient Streaming Loader for Large-Scale Network Traffic Processing." Available: `/PLAN_MEMORY_EFFICIENT_LOADER.md`, 2024.

[2] M. Ring, S. Wunderlich, D. Grüdl, D. Landes, and A. Hotho, "A Survey of Network-based Intrusion Detection Data Sets," *Computers & Security*, vol. 86, pp. 147-167, 2019.

[3] G. Draper-Gil, A. H. Lashkari, M. S. I. Mamun, and A. A. Ghorbani, "Characterization of Encrypted and VPN Traffic using Time-related Features," in *Proc. 2nd International Conference on Information Systems Security and Privacy (ICISSP)*, 2016, pp. 407-414.

[4] Wireshark Community, "Analyzing Large PCAP Files," Wireshark Q&A Forum. [Online]. Available: https://osqa-ask.wireshark.org/questions/50975/analyzing-large-pcap-files-46gb-in-wireshark/

[5] K. Brager, "Forensics Sources Part 1: Packet Capture (PCAP)," *I Help Women In Tech Earn More Money* (Blog), 2024. [Online]. Available: https://www.keirstenbrager.tech/pcap1/

[6] Endace, "PCAP Files Explained: Packet Capture Format and Analysis," 2024. [Online]. Available: https://www.endace.com/learn/what-is-a-pcap-file

[7] K. Moore, "Network Forensics with Wireshark and Brim: Analyzing a PCAP from an Agent Tesla Infection," *malwr0nwind0z.com*, 2023. [Online]. Available: https://malwr0nwind0z.github.io/blog/post_7-25-23_network_forensics_agent_tesla/

[8] M. A. Ambusaidi, X. He, P. Nanda, and Z. Tan, "Building an Intrusion Detection System Using a Filter-Based Feature Selection Algorithm," *IEEE Transactions on Computers*, vol. 65, no. 10, pp. 2986-2998, 2016.

[9] Microsoft Azure Documentation, "Perform Network Intrusion Detection by Using Open-Source Tools," 2024. [Online]. Available: https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-intrusion-detection-open-source-tools

[10] Suricata IDS Documentation, "Suricata User Guide," Open Information Security Foundation, 2024.

[11] J. Zhang, Y. Ling, X. Fu, X. Yang, G. Xiong, and R. Zhang, "Network Traffic Classification Model Based on Attention Mechanism and Spatiotemporal Features," *EURASIP Journal on Information Security*, vol. 2023, article 5, 2023. [Online]. Available: https://jis-eurasipjournals.springeropen.com/articles/10.1186/s13635-023-00141-4

[12] S. Lim, S. Yoo, and J. Choi, "Interactive Web-Based Visual Analysis on Network Traffic Data," *Information*, vol. 14, no. 1, article 16, 2022. [Online]. Available: https://www.mdpi.com/2078-2489/14/1/16

[13] N. Moustafa and J. Slay, "UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems (UNSW-NB15 Network Data Set)," in *Proc. 2015 Military Communications and Information Systems Conference (MilCIS)*, 2015, pp. 1-6.

[14] T. N. Dang, N. Pendar, and A. G. Forbes, "TimeArcs: Visualizing Fluctuations in Dynamic Networks," *Computer Graphics Forum*, vol. 35, no. 3, pp. 61-69, 2016. DOI: 10.1111/cgf.12882 [Online]. Available: https://onlinelibrary.wiley.com/doi/abs/10.1111/cgf.12882

---

## Additional References (for Related Work section)

[15] C. Yin, Y. Zhu, J. Fei, and X. He, "A Deep Learning Approach for Intrusion Detection Using Recurrent Neural Networks," *IEEE Access*, vol. 5, pp. 21954-21961, 2017.

[16] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," in *Proc. 4th International Conference on Information Systems Security and Privacy (ICISSP)*, 2018, pp. 108-116.

[17] O. Barut, Y. Luo, T. Zhang, W. Li, and P. Li, "NetML: A Challenge for Network Traffic Analytics," arXiv preprint arXiv:2004.13006, 2020. [Online]. Available: https://arxiv.org/pdf/2004.13006

[18] Y. Chen, J. Zhang, and C. Wang, "PCAPVision: PCAP-Based High-Velocity and Large-Volume Network Failure Detection," in *Proc. 2024 SIGCOMM Workshop on Networks for AI Computing*, ACM, 2024. [Online]. Available: https://dl.acm.org/doi/10.1145/3672198.3673796

[19] VizSec Community, "Visualization for Cyber Security Datasets," 2024. [Online]. Available: https://vizsec.org/data/

[20] NetResec, "Analyzing 85 GB of PCAP in 2 Hours," NetResec Blog, 2013. [Online]. Available: https://www.netresec.com/?page=Blog&month=2013-01&post=Analyzing-85-GB-of-PCAP-in-2-hours

---

## Notes for Authors

### Citation Style
This introduction uses IEEE citation style (numbered references). Adjust to your target journal/conference requirements (e.g., ACM, APA).

### Key Citations to Verify
- **[1]**: Internal project documentation - consider replacing with published version or formal technical report
- **[4-7]**: Blog posts and community forums - strengthen with peer-reviewed sources if available
- **[14]**: Core TimeArcs paper - **VERIFIED** (Dang et al., 2016, Computer Graphics Forum)

### Recommended Additions
1. **Attack dataset citations**: Add references to specific attack datasets used (e.g., CICIDS2017, UNSW-NB15)
2. **Performance metrics**: Consider citing network visualization performance benchmarks
3. **User study validation**: If you conducted user studies, cite methodology (e.g., SUS, NASA-TLX)
4. **Competing systems**: Add citations for Wireshark, Zeek/Bro, Arkime for comparison

### Strengthening Opportunities
- Add quantitative claims where possible (e.g., "reducing analysis time by X%")
- Include specific attack types from your dataset (malware families, CVE numbers)
- Reference network security frameworks (MITRE ATT&CK, Cyber Kill Chain)

### Target Venues
This introduction is suitable for:
- **IEEE Transactions on Visualization and Computer Graphics (TVCG)**
- **ACM SIGCOMM/IMC** (networking focus)
- **IEEE Symposium on Visualization for Cyber Security (VizSec)**
- **USENIX Security Symposium** (security focus)

---

## Word Count
- Section 1.1-1.6: ~1,250 words
- Typical journal introduction: 1,500-2,500 words
- **Recommendation**: Expand Section 1.2 with specific attack examples or add Section 1.7 on contributions/novelty

