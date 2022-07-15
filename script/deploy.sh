#/bin/sh

bin=user

jump_ssh=root@ymipro.com
deploy_root=/services/deploy/
build_root=tmp/
target_root=/services/${bin}/

if [ -f ${build_root}${bin} ];then
  rm -rf ${build_root}${bin}
fi

if [ ! -d ${build_root} ];then
  mkdir -p ${build_root}
fi


CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o ${build_root}${bin} cmd/${bin}/${bin}.go

ssh ${jump_ssh} "rm -rf ${deploy_root}${bin}.bak"
ssh ${jump_ssh} "cp ${deploy_root}${bin} ${deploy_root}${bin}.bak"
scp ${build_root}${bin} ${jump_ssh}:${deploy_root}
ssh ${jump_ssh} "cd ${deploy_root} && bash ./_deploy_v3.sh /services/dev/${bin} ${bin}"
