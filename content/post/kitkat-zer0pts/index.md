---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "Locked KitKat"
subtitle: ""
summary: ""
authors: []
tags: []
categories: []
date: 2020-03-11T19:43:45+01:00
lastmod: 2020-03-11T19:43:45+01:00
featured: false
draft: false
authors:
  - iwd
tags:
  - foren
  - zer0pts
# Featured image
# To use, add an image named `featured.jpg/png` to your page's folder.
# Focal points: Smart, Center, TopLeft, Top, TopRight, Left, Right, BottomLeft, Bottom, BottomRight.
image:
  caption: ""
  focal_point: ""
  preview_only: false

# Projects (optional).
#   Associate this post with one or more of your projects.
#   Simply enter your project's folder or file name without extension.
#   E.g. `projects = ["internal-project"]` references `content/project/deep-learning/index.md`.
#   Otherwise, set `projects = []`.
projects: []
---

# Locked kitkat



The challenge :
We've extracted the internal disk from the Android device of the suspect. Can you find the pattern to unlock the device? Please submit the correct pattern here.

Extract gesture.key

Method 1 : 
mount the given image and search for gesture.key , which is usually on data/system/

```sh
$ mkdir andr
$ sudo mount -o loop android.4.4.x86.img andr
$ find andr/ -name gesture.key
```



Method 2: extract using fls : 

first we need to search for parameter of the file which we want to extract! 

```sh
$fls android.4.4.x86.img -r | grep -i gesture.key
+ r/r 8495:    gesture.key
```

Now we know the address of gesture.key , extract it using icat

```sh
$icat android.4.4.x86.img 8495 > gesture.key
```

And now we get the file. 

![](1.png)

I'I crack the gesture Using [P-Decode](https://github.com/MGF15/P-Decode ) we can easily get the pattern of the phone

```sh
$python P-Decode-master/P-Decode.py -f gesture.key
```

![](2.png)

![](4.svg)

 And we get the pattern in image. Finally We submit at the given website and get the flag

![](3.png)

```
zer0pts{n0th1ng_1s_m0r3_pr4ct1c4l_th4n_brut3_f0rc1ng}
```

