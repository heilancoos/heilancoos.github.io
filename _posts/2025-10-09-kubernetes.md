---
title: "A Brief Deep-Dive into Attacking and Defending Kubernetes"
layout: post-with-toc
background: '/img/kubernetes/thumbnail.png'
subtitle: "What attackers do in Kubernetes and how to catch them."
image: 'https://heilancoos.github.io/img/kms-ransomware/kms-ransomware-diagram.png'
excerpt: "What attackers do in Kubernetes—and how to catch them."  # <-- used for description/meta
tags: [research, cloud, containers, security]
categories: [research]
---



## How Kubernetes Works
Kubernetes (K8s) is an open source platform for container management. Within K8s, users are able to deploy and manage applications in a distributed system environment.

K8s has become a staple for many DevOps teams, with 60% of companies adopting it in 2025\. Kubernetes can be quite complicated for newcomers.

Here are the basics you need to know for this blog.

The Control Plane is where a lot of the management work is done. It has 4 main components: 

* The API server  
  * The user tells the API Server what to do using `kubectl` and the API server orchestrates the rest.  
* etcd  
  * This is a key-value store that holds all cluster data like pods and secrets.  
* Scheduler   
  * The Scheduler decides which node the pods should run on.  
* Controller Manager  
  * The Controller Manager ensures that everything is running as configured. For example if the deployment says 3 replicas, the Controller Manager will make sure there are always 3 pods running.

Nodes are the workers that actually run the apps. Each node has `kubelet` which talks to the API server and manages the pods in the node. `kube-proxy` handles the networking and service routing. And finally, pods are the smallest deployable units.

![image01](/img/kubernetes/ControlPlane.png){: width="720" .mx-auto .d-block }

Kubernetes is very powerful but every component of Kubernetes can be vulnerable if misconfigured. Attackers abuse these misconfigurations in order to achieve their objectives. 

To better understand and organize these threats, Microsoft released a threat matrix for Kubernetes.

 ![image02](/img/kubernetes/threat-matrix.png){: width="840" .mx-auto .d-block }

In this blog I will cover some of the most pertinent attack techniques affecting Kubernetes clusters in the wild. I'll also use Falco to engineer detections and provide actionable mitigations for the attacks.

## Threat Hunting in Kubernetes

With Kubernetes as complex and vast as it is, visibility into threats in the environment become harder to detect. Luckily, there are open-source tools that exist to fill this gap.

Falco and FalcoSideKick UI are open-source security tools that can be used for threat hunting within Kubernetes.

Falco is able to ingest Kubernetes logs and detect tactics, techniques, and procedures (TTPS). Falco Sidekick serves as the frontend user interface.

Example detection in Falco:

![image03](/img/kubernetes/falco-example.png)

Falco can also forward logs to multiple third-party platforms like Slack, Datadog, ElasticSearch, Prometheus, and more.

![image04](/img/kubernetes/image.png)
