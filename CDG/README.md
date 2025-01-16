# git 避免提交 mac 的 .DS_Store 文件

1.在项目下创建 .gitignore 文件，然后写入如下内容

```.DS_Store
.DS_Store
```



2.在项目内输入以下命令，会删除当前文件夹及子文件夹下的 .DS_Store

```
find . -name .DS_Store -print0 | xargs -0 git rm -f --ignore-unmatch
```



3.提交到远程

```
git add .
git commit -m 'delete .DS_Store'
git push --force
```

