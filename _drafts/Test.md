---
title: Test post
date: 2022-01-18 14:30:00 +0000
categories: [test]
tags: [test]     # TAG names should always be lowercase
author: zodi4c
---

# Introduction

Hi! This is a test.


## Code

```rust
let Some((pid, version)) = version_map.iter().find_map(|(name, version)| {
    utils::process_pid_by_name(name).map(|pid| (pid, version))
}) else {
    bail!("no minesweeper in memory!");
};
```
{: file="test.rs" }

## Tooltip

> This is a test tooltip. They look fun! =)
{: .prompt-info }

The file `/etc/hostname`{: .filepath} is interesting.

# Ending

Here is the flag:
{L0rREm_1psUM_864ac7}
