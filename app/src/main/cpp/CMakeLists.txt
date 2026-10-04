cmake_minimum_required(VERSION 3.18)
project(lqkey C)

# 仅生成一个极小的 .so，不链接任何第三方库
add_library(lqkey SHARED lqkey.c)
