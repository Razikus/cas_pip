PROTO_DIR := protos
# grpc-gateway https://github.com/grpc-ecosystem/grpc-gateway/tree/v1.16.0
# immudb https://github.com/codenotary/immudb/tree/master/pkg/api/schema
# lc https://github.com/vchain-us/ledger-compliance-go/blob/master/schema/lc.proto

# After generating model you have to change imports inside models to use relatives
# from . import something as something instead of
# import something as something

GRPC_GATEWAY := grpcgatewayrepo
PROTO_FILE := ${PROTO_DIR}/*.proto
PROTOC_INCLUDE_PATH_GOOGLE := 	-I${GRPC_GATEWAY} -I ${GRPC_GATEWAY}/third_party/googleapis 
PROTOC_INCLUDE_PATH := 	-I${PROTO_DIR}

.PHONY: ${PROTO_DIR}
${PROTO_DIR}:
	rm -rf ${GRPC_GATEWAY}
	git clone https://github.com/grpc-ecosystem/grpc-gateway.git -b v1.16.0 --depth=1 ${GRPC_GATEWAY}
	curl https://raw.githubusercontent.com/vchain-us/ledger-compliance-go/master/schema/lc.proto -o ${PROTO_DIR}/lc.proto
	curl https://raw.githubusercontent.com/codenotary/immudb/master/pkg/api/schema/schema.proto -o ${PROTO_DIR}/schema.proto
	python3 -m grpc_tools.protoc \
		${PROTO_FILE} \
		--proto_path=./${PROTO_DIR} \
		${PROTOC_INCLUDE_PATH} \
		${PROTOC_INCLUDE_PATH_GOOGLE} \
		--python_out=. \
		--grpc_python_out=.
	touch protoc_gen_swagger/__init__.py
	touch protoc_gen_swagger/options/__init__.py
	touch __init__.py
	rm -rf ${GRPC_GATEWAY}
