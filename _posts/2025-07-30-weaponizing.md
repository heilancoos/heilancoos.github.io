---
title: "Weaponizing Reality: The Evolution of Deepfakes"
layout: post
background: '/img/leadspace_article.png'
subtitle: "A blog discussing the evolution of deepfakes"
artist: "socialmediasafety.org"
tags: [research, ai, security]
categories: [research]
---
**Originally posted on IBM Think here:** [Blog Link](https://www.ibm.com/think/x-force/weaponizing-reality-evolution-deepfake-technology)

## Overview
Phishing is no longer just about spotting the obvious scam, now it means questioning if that call from your friend or boss is even real. With the rise of artificial intelligence, malicious actors are only growing stealthier and more sophisticated. Social engineering remains one of the top attack vectors that lead to a breach. This has been mitigated by employee training and advanced spam filters but in 2024, over[ 80% of companies reported they have no protocols in place to fight back against deepfake-based attacks](https://www.forbes.com/sites/edwardsegal/2024/11/10/80-of-surveyed-businesses-dont-have-plans-for-an-ai-related-crisis/). In 2024, [Pindrop's 2025 Voice Intelligence Report found](https://cybertechnologyinsights.com/threat-management/pindrops-2025-report-shows-1300-percent-spike-in-deepfake-fraud-cases/) a sharp up tick in  deepfake fraud compared to previous years by a 1300% increase. Deepfake attacks represent a daunting new frontier, one where you can no longer trust what you see.

## What exactly are "deepfakes"?

The term "deepfake" was coined in 2017 by a reddit user operating under the name "deepfakes". Using an account dedicated to adult content, he released some of the first publicly distributed deepfake videos.

The actual technology behind deepfakes originated in 2014 with a research paper published by Ian Goodfellow. A [Generative Adversarial Network](https://www.ibm.com/think/topics/generative-adversarial-networks) (GAN) is a type of machine learning model that generates new data by learning patterns from training datasets. But what does this actually mean?
	A GAN consists of two neural networks that constantly compete with each other to create realistic fake data. One network is the Generator, the other is the Discriminator. 
		- The Generator creates synthetic content.
		- The Discriminator determines whether or not the content is real. 
	This back and forth eventually makes the fake content look as real as possible. Think of it like sharpening a sword against a steel block. Every time the sword (the Generator) is run against the steel block (the Discriminator), the sword gets sharper.

![Alt text](/img/how-gans-work.jpg)

Early deepfakes were usually low quality and easy to spot. Today, that's no longer the case

Deepfakes entered the mainstream in 2018, with the release of accessible open-source deepfake tools like DeepFaceLab. Since then, the technical barriers to create realistic deepfakes have steadily declined. Unfortunately, the creation of non consensual explicit content of women has served as a motivating factor for the popularization of deepfake tools. The problem is rampant, with [Security Hero](https://www.securityhero.io/state-of-deepfakes/) reporting that in 2023, approximately 98% of deepfake videos online are explicit in nature.

In recent years, deepfakes have also been used to manipulate politics and consumer fraud. Most of the targets of deepfakes are public figures largely due to the fact that they have a wealth of media samples available on the internet. 

In early 2024, [New Hampshire constituents](https://apnews.com/article/new-hampshire-primary-biden-ai-deepfake-robocall-f3469ceb6dd613079092287994663db5) received a robocall that impersonated President Biden to discourage voting in the Democratic primary election. The malicious actor even spoofed  the caller ID to appear as the Democratic Party chair. This incident is  a clear example of voice phishing aka "vishing", using deepfake audio.

There have also been multiple deepfake videos featuring prominent public figures such as Elon Musk, the New Zealand Prime Minister [Christopher Luxon](https://www.rnz.co.nz/news/national/531353/pensioner-loses-224k-after-being-tricked-by-ai-deepfake-christopher-luxon-cryptocurrency-investment-scam), and the [Canada Prime Minister]([Ontario man loses $12K to deepfake scam involving Prime Minister Justin Trudeau](https://www.ctvnews.ca/toronto/article/ontario-man-loses-12k-to-deepfake-scam-involving-prime-minister-justin-trudeau/)). These deepfake videos promoted various cryptocurrency schemes to scam unknowing investors.

There are also more legitimate uses of deepfake technology with [researchers at MIT's Center for Advanced Virtuality](https://news.mit.edu/2020/mit-tackles-misinformation-in-event-of-moon-disaster-0720) deepfaking President Richard Nixon delivering a speech about a failed moon landing. This project was created to warn about the importance of media literacy in the age of deepfakes. [Disney](https://boldentrance.com/will-disney-researchs-ai-fran-revolutionize-re-aging-of-actors/) and other major Hollywood studios have also been invested in using the technology for de-aging actors and advanced visual effects. 

## Notable Incidents

Below are five notable cases where deepfake technology was used in fraud, deception, and impersonation. 
### Arup
In early 2024, the multinational engineering firm Arup, confirmed that it lost $25 million to a deepfake scam.

[A Hong Kong employee](https://www.cnn.com/2024/05/16/tech/arup-deepfake-scam-loss-hong-kong-intl-hnk) received a phishing email from the Arup's UK office requesting a "secret" transaction. Naturally the employee was suspicious at first. His suspicion was put to rest when he joined a video call with the Chief Financial Officer and several other employees. He recognized these faces and their voices, so he sent 200 million Hong Kong dollars ($25.6M USD). The money was sent in 15 transfers to [five different banks](https://www.techmonitor.ai/technology/cybersecurity/arup-revealed-as-victim-of-25m-deepfake-scam?cf-view) before the fraud was discovered.

The Chief Information Officer Rob Greig discussed the incident at the time with the [World Economic Forum](https://www.weforum.org/stories/2025/02/deepfake-ai-cybercrime-arup/). Greig described the incident as more "technology-enhanced social engineering" rather than a cyber attack. There was no system compromise or unauthorized data access. People were tricked into carrying out what they thought were genuine transactions. Greig even tried to create deepfake video of himself and it took him less than an hour. He also believes this happens more often than people might think.

This case highlights the devastating financial damage deepfake phishing can have on a company. Similar cases have targeted individuals  as well, with senior citizens receiving distress calls impersonating their loved ones.


### High School Principal Incident

The danger of deepfakes does not only extend to public figures and company executives. In 2024, a case emerged of [a principal in Baltimore](https://www.bbc.com/news/world-us-canada-68907895) who had his life turned upside down because of an AI-generated audio clip of him appearing to make racist and antisemitic statements.

A fabricated audio clip of the principal of Pikesville High School, Eric Eiswert, went viral online as he appeared to make harmful and derogatory statements. The clip received well over two million views. There was immense backlash both online and in real life. The local community especially were outraged as Pikesville has a large black and Jewish population.

Due to the backlash, Eiswert went on leave and police were stationed to guard his home amidst the vicious threats and harassment he was receiving. Security was also increased at the school. 

Eiswert's initial defense that the clip was fake was [poorly received](https://www.bbc.com/news/articles/ckg9k5dv1zdo) and dismissed as Eiswert avoiding accountability. The clip was initially posted in January 2024. It took until April for the local police confirmed the recording was falsified. Police arrested the school's athletic director, Dazhon Darien with charges related to the fake clip. Eiswert had been investigating Darien for a theft of school money and work performance issues. In April 2025, Dazhon Darien pleaded guilty, having purchased AI cloning tools.

The incident had damaging effects on Eiswert's reputation, leaving Eiswert to move jobs and work in another school.

### UK CEO Voice Fraud

One of the first major deepfake attacks occurred in 2019 when deepfake audio was [used to steal $243, 000](https://www.trendmicro.com/vinfo/mx/security/news/cyber-attacks/unusual-ceo-fraud-via-deepfake-audio-steals-us-243-000-from-u-k-company) from a UK company.

**The Facts:**

The CEO of an unnamed UK energy company received a call from the CEO of the German parent company. The [UK CEO noted](https://www.forbes.com/sites/jessedamiani/2019/09/03/a-voice-deepfake-was-used-to-scam-a-ceo-out-of-243000/) that the the call even carried the "melody" of the German CEO. The fraudsters called a total of three times. In the first call, the fraudster requested the UK CEO to transfer $243,000 to the bank account of a Hungarian supplier. The CEO complied. In the second call, they claimed the transfer was reimbursed. The third and final call, the caller was seeking a follow-up payment. After the UK CEO noticed the transfer was in fact not reimbursed, he refused to send any follow-up payments. The first transfer was transferred to the Hungarian bank account, then to Mexico and elsewhere, making attribution difficult.

This early deepfake fraud case a canary for how ambitious and sohpisticated these schemes would later become.

### Threat Actor Group BlueNoroff Crypto Scheme
As one of the more recent attacks occurring in June 2025, the threat actor group based in North Korea, BlueNoroff, utilized deepfake technology to target cryptocurrency companies.

**The Facts:**

A cryptocurrency company employee received a Calendly link for a Google meet. Two weeks later, the employee joined a Zoom call [controlled by the threat actor](https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis). The call was filled deepfaked versions of senior leadership. When the employee experienced an audio issue, the attackers sent a malicious Zoom Extension. The Zoom Extension was actually a script that deployed malware to hijack any crypto wallets found on the system.

This attack highlights how threat actors are now combining traditional social engineering with real-time deepfake impersonation, making verification significantly harder for end users.


## Conclusion

Deepfakes are no longer a potential threat, the threat and its consequences are very real and present. The threat is not isolated to celebrities, anyone can be affected. As shown in recent attacks, the barrier to entry for creating realistic deepfakes has dramatically decreased. From cloned voices to full video impersonations, deepfakes empower scammers and fraudsters in ways that are harder to detect and defend against. 

Understanding the threat is the first step to defending against it. With more end-user security training and leveraging emerging deepfake detection tools, organizations and individuals can begin to fight back against this new threat.