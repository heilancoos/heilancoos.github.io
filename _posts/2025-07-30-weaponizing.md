---
title: "Weaponizing Reality: The Evolution of Deepfakes"
layout: post
background: '/img/leadspace_article.png'
subtitle: "Deepfakes are quickly becoming into a powerful tool for deception and manipulation. This blog examines the evolution of deepfake-based attacks, analyzing various real cases."
artist: "socialmediasafety.org"
tags: [research, ai, security]
categories: [research]
---
**Originally posted on IBM Think here:** [Blog Link](https://www.ibm.com/think/x-force/weaponizing-reality-evolution-deepfake-technology)

## Overview
For decades, phishing attacks have been playing on human emotions to scam them out of account credentials and money and still do. But as technology advanced leaps and bounds since the first phishing cases in the 1990’s, phishing is no longer just about spotting the obvious scam message with typos and grammatical mistakes. Now it means questioning if that call from your friend or boss is even real – even if it sounds exactly like them. With the rise of artificial intelligence, malicious actors are only growing stealthier and more sophisticated, and everyone needs to rethink what is real, get used to looking for fake signals, and learn how to better protect their identities on and offline. 

Social engineering is the umbrella term for a plethora of ways by which attackers and fraudsters manage to trick people into divulging information that will compromise their identity and accounts. This threat also remains one of the top attack vectors that leads to a [data breach](https://www.ibm.com/reports/threat-intelligence). This has been mitigated to an extent by employee training and advanced spam filters but does not appear to apply to the trending Deepfake threat. In 2024, over [80% of companies reported they have no protocols in place to fight back against Deepfake-based attacks](https://www.forbes.com/sites/edwardsegal/2024/11/10/80-of-surveyed-businesses-dont-have-plans-for-an-ai-related-crisis/).

Furthermore, [Pindrop's 2025 Voice Intelligence Report](https://cybertechnologyinsights.com/threat-management/pindrops-2025-report-shows-1300-percent-spike-in-deepfake-fraud-cases/) found a sharp uptick in Deepfake fraud compared to previous years reporting a 1300% increase. Deepfake attacks represent a daunting new frontier, one where you can no longer trust what you see – or hear.

## What exactly are "deepfakes"?

The technology behind deepfakes is called [Generative Adversarial Network](https://www.ibm.com/think/topics/generative-adversarial-networks) (GAN). It was developed in 2014 and published in a research paper by researcher [Ian Goodfellow](https://en.wikipedia.org/wiki/Ian_Goodfellow), and his colleagues. A GAN is a type of machine learning model that generates new data by learning patterns from training datasets. But what does this actually mean? A GAN consists of two neural networks that constantly compete with each other to create realistic, fake data. One network is the Generator, the other is the Discriminator. 

The Generator creates synthetic content, and the Discriminator determines whether the content is real. This back and forth eventually makes the fake content look as real as possible. Think of it like sharpening a sword against a steel block. Every time the sword (the Generator) is run against the steel block (the Discriminator), the sword gets sharper. 


![https://pilot44.com/insights/the-evolution-of-generative-ai](/img/how-gans-work.jpg)

A few years later, in 2017, the term "deepfake" was coined by a Reddit user operating under the name "deepfakes". This person abused the GAN concept in a malicious way. Using an account dedicated to adult content, he released some of the first publicly distributed deepfake videos using images of unrelated personspeople to create fake content and distribute it online. 

While early deepfakes were usually low quality and easier to spot. Today, that's no longer the case. People are posting voice and image deepfakes which are very hard to identify as fake, challenging the very concept of identity and trust in the virtual world.

## Deepfake Timeline - Deeply Disturbing
Deepfakes entered the mainstream in 2018, with the release of accessible open source deepfake tools like DeepFaceLab. Since then, the technical barriers to creating realistic deepfakes have steadily declined. In 2023, the deepfake tool market skyrocketed, with a 44% increase in development of these tools. Unfortunately, the creation of non-consensual explicit content of women has served as a motivating factor for the popularization of deepfake tools. The problem is rampant, with [Security Hero](https://www.securityhero.io/state-of-deepfakes/) reporting that in 2023, approximately 98% of deepfake videos online are explicit in nature and only 1% of targets in that category are male.

In recent years, deepfakes have also been used to manipulate politics and consumer fraud. Most of the targets of deepfakes are public figures, largely because they have a wealth of media samples available on the internet.

In early 2024, [New Hampshire constituents](https://apnews.com/article/new-hampshire-primary-biden-ai-deepfake-robocall-f3469ceb6dd613079092287994663db5) received a robocall that impersonated President Biden to discourage them from voting in the Democratic primary election. The malicious actor even spoofed the caller ID to appear as the Democratic Party chair. This incident is a clear example of voice phishing, a.k.a. "vishing", using deepfake audio. Since then, [the FCC has banned the use of AI-generated voices in robocalls](https://apnews.com/article/fcc-elections-artificial-intelligence-robocalls-regulations-a8292b1371b3764916461f60660b93e6) for voter suppression.

There have also been multiple deepfake videos featuring prominent public figures such as  [Elon Musk](https://www.engadget.com/deepfakes-of-elon-musk-are-pushing-crypto-giveaway-scams-on-youtube-live-200700886.html), the New Zealand Prime Minister, [Christopher Luxon](https://www.rnz.co.nz/news/national/531353/pensioner-loses-224k-after-being-tricked-by-ai-deepfake-christopher-luxon-cryptocurrency-investment-scam) and [Canadian Prime Minister Justin Trudeau](https://www.ctvnews.ca/toronto/article/ontario-man-loses-12k-to-deepfake-scam-involving-prime-minister-justin-trudeau/). These deepfake videos promoted various cryptocurrency schemes to scam potential investors.

There are also more legitimate uses of deepfake technology, with [researchers at MIT's Center for Advanced Virtuality](https://news.mit.edu/2020/mit-tackles-misinformation-in-event-of-moon-disaster-0720) deepfaking President Richard Nixon delivering a speech about a failed moon landing. This project was created by students to warn about the importance of media literacy in the age of deepfakes. [Disney](https://boldentrance.com/will-disney-researchs-ai-fran-revolutionize-re-aging-of-actors/) and other major Hollywood studios have also invested in using the technology for de-aging actors and including advanced visual effects in movies.

## Notable incidents using deepfakes
Below are four notable cases where deepfake technology was used in fraud, deception and impersonation.

### Arup
In early 2024, the multinational engineering firm Arup confirmed that it lost USD25 million to a deepfake scam.

A [Hong Kong employee](https://www.cnn.com/2024/05/16/tech/arup-deepfake-scam-loss-hong-kong-intl-hnk) received a phishing email from Arup's UK office requesting a "secret" transaction. Naturally, the employee was suspicious at first. His suspicion was put to rest when he joined a video call with the Chief Financial Officer and several other employees. He recognized these faces and their voices, so he sent 200 million Hong Kong dollars (USD25.6M). The money was sent in 15 transfers to [five different banks](https://www.techmonitor.ai/technology/cybersecurity/arup-revealed-as-victim-of-25m-deepfake-scam?cf-view) before the fraud was discovered.

Arup's Chief Digital Information Officer, Rob Greig, discussed the incident at the time with the [World Economic Forum](https://www.weforum.org/stories/2025/02/deepfake-ai-cybercrime-arup/). Greig described the incident as more "technology-enhanced social engineering" rather than a cyberattack. There was no system compromise or unauthorized access to data. People were tricked into carrying out what they thought were genuine transactions. Greig even tried to create a deepfake video of himself, and it took him less than an hour. He also believes this happens more often than people might think.

This case highlights the devastating financial damage deepfake phishing can have on a company. Similar cases have targeted individuals as well, with senior citizens receiving distress calls impersonating their loved ones.

### High school principal incident
The danger of deepfakes extends not only to public figures and company executives. In 2024, a case emerged of [a principal in Baltimore](https://www.bbc.com/news/world-us-canada-68907895) who had his life turned upside down because of an AI-generated audio clip of him appearing to make racist and antisemitic statements.

A fabricated audio clip of the principal of Pikesville High School, Eric Eiswert, went viral online as he appeared to make harmful and derogatory statements. The clip received well over two million views. There was immense backlash both online and in real life. The local community was especially outraged as Pikesville has a large black and Jewish population.

Due to the backlash, Eiswert went on leave, and police were stationed to guard his home amidst the vicious threats and harassment he was receiving. Security was also increased at the school.

Eiswert's initial defense that the clip was fake was [poorly received](https://www.bbc.com/news/articles/ckg9k5dv1zdo) and dismissed as Eiswert avoiding accountability. The clip was initially posted in January 2024. It took until April for the local police to confirm the recording was falsified. Police arrested the school's athletic director, Dazhon Darien, on charges related to the fake clip. Eiswert had been investigating Darien for theft of school money and work performance issues. In April 2025, Dazhon Darien pleaded guilty, having purchased AI cloning tools.

The incident had damaging effects on Eiswert's reputation, leaving Eiswert to move jobs and work in another school.

### UK CEO voice fraud
One of the first major deepfake attacks occurred in 2019 when deepfake audio was [used to steal USD243,000](https://www.trendmicro.com/vinfo/mx/security/news/cyber-attacks/unusual-ceo-fraud-via-deepfake-audio-steals-us-243-000-from-u-k-company) from a UK company.

The CEO of an unnamed UK energy company received a call from the CEO of the German parent company. The [UK CEO noted](https://www.forbes.com/sites/jessedamiani/2019/09/03/a-voice-deepfake-was-used-to-scam-a-ceo-out-of-243000/) that the call even carried the "melody" of the German CEO. The fraudsters called a total of three times. In the first call, the fraudster requested the UK CEO to transfer USD243,000 to the bank account of a Hungarian supplier. The CEO complied. In the second call, they claimed the transfer was reimbursed. The third and final call, the caller was seeking a follow-up payment. After the UK CEO noticed the transfer was, in fact, not reimbursed, he refused to send any follow-up payments. The first amount was transferred to the Hungarian bank account, then to Mexico and elsewhere, making attribution difficult.

This early deepfake fraud case is a canary for how ambitious and sophisticated these schemes would later become.

### Threat actor group BlueNoroff crypto scheme
As one of the more recent attacks occurring in June 2025, the threat actor group based in North Korea, BlueNoroff, utilized deepfake technology to target cryptocurrency companies.

A cryptocurrency company employee received a Calendly link for a Google Meet. Two weeks later, the employee joined a Zoom call [controlled by the threat actor](https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis). The call was filled with deepfaked versions of senior leadership. When the employee experienced an audio issue, the attackers sent a malicious Zoom Extension. The Zoom Extension was actually a script that deployed malware to hijack any crypto wallets found on the system.

This attack highlights how threat actors are now combining traditional social engineering with real-time deepfake impersonation, making verification significantly harder for end users.

### A threat to reckon with
Deepfakes are no longer a potential threat; the threat and its consequences are [very real and present](https://www.dhs.gov/sites/default/files/publications/increasing_threats_of_deepfake_identities_0.pdf). Deepfakes today are at the point of undermining trust in the online identity verification process that many organizations, especially in the financial sector, have come to rely upon. With more people than ever authenticating themselves using biometrics across all their devices, the growth in the malicious use of deepfakes can lead to a dire need to [rethink authentication security](https://www.forbes.com/councils/forbestechcouncil/2024/08/02/in-the-deepfake-era-its-time-to-overhaul-identity-verification/) within the next five years, or sooner.

As shown in recent attacks, the barrier to entry for creating realistic deepfakes has dramatically decreased. From cloned voices to full video impersonations, deepfakes empower scammers and fraudsters in ways that are harder to detect and defend against.

Another aspect that should be taken seriously is the use of deepfakes by school bullies who taunt and harass their peers, target educators or try to depict themselves in situations that are meant to threaten and intimidate others. [This cyberbullying trend](https://www.neari.org/advocating-change/new-from-neari/ai-deepfakes-disturbing-trend-school-cyberbullying) is only getting worse over time, and calls on parents to educate children and be very vigilant about potential threats.

Understanding the threat is the first step to defending against it. With more end-user security training and leveraging emerging deepfake detection tools, organizations and individuals can begin to fight back against this new threat.

*Want to learn more? Contact X-Force experts for a 1:1 briefing and talk about deepfakes, deepfake threats and how your team can train to identify them and thwart threat actors before damage is done.*

*Our Cyber Range team invites you to train like you fight at one of our global locations, your offices or virtually. [Contact us today](https://www.ibm.com/services/xforce-cyber-range).*