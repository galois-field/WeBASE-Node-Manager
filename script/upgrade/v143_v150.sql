-- SET NAMES utf8mb4;
-- SET FOREIGN_KEY_CHECKS = 0;
-- TODO 这里的所有数据 ddl与dml中均存在.


CREATE TABLE IF NOT EXISTS tb_app_info
(
    id           bigserial    NOT NULL,
    app_name     varchar(128) NOT NULL,
    app_key      varchar(16)  NOT NULL,
    app_secret   varchar(32)           DEFAULT NULL,
    app_type     smallint     NOT NULL DEFAULT '2',
    app_status   smallint     NOT NULL DEFAULT '2',
    app_doc_link varchar(256)          DEFAULT NULL,
    app_link     varchar(256)          DEFAULT NULL,
    app_ip       varchar(16)           DEFAULT NULL,
    app_port     int                   DEFAULT NULL,
    app_icon     text                  DEFAULT NULL,
    app_desc     varchar(1024)         DEFAULT NULL,
    app_detail   text                  DEFAULT NULL,
    create_time  timestamp             DEFAULT NULL,
    modify_time  timestamp             DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE (app_key)
);
-- TODO 同理忽略此处单独命名索引
-- CREATE UNIQUE INDEX uk_key ON tb_app_info (app_key);
-- CREATE INDEX uk_name ON tb_app_info (app_name);

-- ----------------------------
-- Table structure for tb_contract_store
-- ----------------------------
CREATE SEQUENCE IF NOT EXISTS tb_contract_store_id START 300001;
CREATE TABLE IF NOT EXISTS tb_contract_store
(
    id bigint NOT NULL DEFAULT nextval('tb_contract_store_id'),
    app_key          varchar(16)  NOT NULL,
    contract_name    varchar(120) NOT NULL,
    contract_version varchar(120) NOT NULL,
    contract_source  text,
    contract_abi     text,
    bytecode_bin     text,
    account          varchar(50) DEFAULT 'admin',
    create_time      timestamp   DEFAULT NULL,
    modify_time      timestamp   DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE (app_key, contract_name, contract_version)
);
-- TODO 同理忽略此处单独命名索引
-- CREATE UNIQUE INDEX uk_version ON tb_contract_store (app_key, contract_name, contract_version);

CREATE TABLE IF NOT EXISTS tb_stat
(
    id             bigserial NOT NULL,
    group_id       int       NOT NULL,
    block_cycle    bigserial DEFAULT '0',
    tps            int       DEFAULT '0',
    block_number   int       DEFAULT '0',
    block_size     int       DEFAULT '0',
    stat_timestamp varchar(64),
    create_time    timestamp DEFAULT NULL,
    modify_time    timestamp DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE (group_id, block_number)
);
-- TODO 同理忽略此处单独命名索引
-- CREATE UNIQUE INDEX uk_block ON tb_stat (group_id, block_number);
-- CREATE INDEX index_group ON tb_stat (group_id);


-- ----------------------------
-- Table structure for tb_external_account 链上外部账户
-- ----------------------------
CREATE TABLE IF NOT EXISTS tb_external_account
(
    id           bigserial NOT NULL,
    group_id     int          DEFAULT NULL,
    address      varchar(64)  DEFAULT NULL,
    public_key   varchar(250) DEFAULT NULL,
    sign_user_id varchar(64)  DEFAULT NULL,
    has_pk       smallint     DEFAULT 1,
    user_name    varchar(64)  DEFAULT NULL,
    user_status  smallint     DEFAULT NULL DEFAULT '1',
    create_time  timestamp    DEFAULT NULL,
    modify_time  timestamp    DEFAULT NULL,
    description  varchar(250) DEFAULT NULL,
    app_id       varchar(64)  DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE (group_id, user_name),
    UNIQUE (group_id, address),
    UNIQUE (sign_user_id)
);
-- TODO 同理忽略此处单独命名索引
-- CREATE UNIQUE INDEX unique_name ON tb_external_account (group_id, user_name);
-- CREATE UNIQUE INDEX unique_address ON tb_external_account (group_id, address);
-- CREATE UNIQUE INDEX unique_uuid ON tb_external_account (sign_user_id);
-- CREATE INDEX index_address ON tb_external_account (address);

-- ----------------------------
-- Table structure for tb_external_contract 链上外部合约
-- ----------------------------
CREATE SEQUENCE IF NOT EXISTS tb_external_contract_id START 800001;
CREATE TABLE IF NOT EXISTS tb_external_contract
(
    id               bigint       NOT NULL DEFAULT nextval('tb_external_contract_id'),
    group_id         int          NOT NULL,
    contract_address varchar(64)  NOT NULL,
    deploy_address   varchar(64)  NOT NULL,
    deploy_tx_hash   varchar(120) NOT NULL,
    deploy_time      timestamp    NOT NULL,
    contract_bin     text                  DEFAULT NULL,
    contract_status  smallint              DEFAULT '1',
    contract_type    smallint              DEFAULT '0',
    contract_name    varchar(120)          DEFAULT NULL,
    contract_version varchar(120)          DEFAULT NULL,
    contract_abi     text,
    bytecode_bin     text,
    create_time      timestamp             DEFAULT NULL,
    modify_time      timestamp             DEFAULT NULL,
    description      text,
    PRIMARY KEY (id),
    UNIQUE (group_id, contract_address)
);
-- TODO 同理忽略此处单独命名索引
-- CREATE UNIQUE INDEX uk_group_path_name ON tb_external_contract (group_id, contract_address);


-- 插入默认数据 --
-- if begin end, else begin end
-- TODO 这里的数据webase-dml中都有,但是后面的v150-v153中的数据dml中没有
INSERT INTO tb_app_info (app_name, app_key, app_type, app_doc_link, app_icon, app_desc, app_detail, create_time,
                         modify_time)
VALUES ('WeId-temp', 'app00001', 1, 'https://weidentity.readthedocs.io/zh_CN/latest/docs/deploy-via-web.html',
        'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAYAAACOEfKtAAAACXBIWXMAAAsTAAALEwEAmpwYAAAFGmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDIgNzkuMTY0MzUyLCAyMDIwLzAxLzMwLTE1OjUwOjM4ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjEuMSAoTWFjaW50b3NoKSIgeG1wOkNyZWF0ZURhdGU9IjIwMjEtMDMtMThUMTY6NTc6MzQrMDg6MDAiIHhtcDpNb2RpZnlEYXRlPSIyMDIxLTAzLTE4VDE4OjAyOjAxKzA4OjAwIiB4bXA6TWV0YWRhdGFEYXRlPSIyMDIxLTAzLTE4VDE4OjAyOjAxKzA4OjAwIiBkYzpmb3JtYXQ9ImltYWdlL3BuZyIgcGhvdG9zaG9wOkNvbG9yTW9kZT0iMyIgcGhvdG9zaG9wOklDQ1Byb2ZpbGU9InNSR0IgSUVDNjE5NjYtMi4xIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOjg1NDJjNjJlLTZjYTUt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',
        'WeIdentity是一套分布式多中心的技术解决方案。',
        'WeIdentity目前主要包含两大模块：WeIdentity DID以及WeIdentity Credential。 WeIdentity DID模块在FISCO-BCOS区块链底层平台上实现了一套符合W3C DID规范的分布式多中心的身份标识协议，使实体（人或物）的现实身份实现了链上的身份标识；WeIdentity Credential提供了一整套基于W3C VC规范的解决方案，旨在对这一类数据进行标准化、电子化，生成可验证、可交换的「凭证」（Credential），支持对凭证的属性进行选择性披露，及生成链上存证（Evidence）。',
        now(), now());
-- init tb_method (openTable/grantWrite/revokeWrite/revokeManager)
-- standard
INSERT INTO tb_method ( method_id, group_id, abi_info, method_type, contract_type, create_time
                      , modify_time)
VALUES ('0xf23f63c9', 0,
        '{"constant":true,"inputs":[{"name":"","type":"string"}],"name":"openTable","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method ( method_id, group_id, abi_info, method_type, contract_type, create_time
                      , modify_time)
VALUES ('0x96ec37c4', 0,
        '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"user","type":"address"}],"name":"grantWrite","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method ( method_id, group_id, abi_info, method_type, contract_type, create_time
                      , modify_time)
VALUES ('0x99c26010', 0,
        '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"user","type":"address"}],"name":"revokeWrite","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method ( method_id, group_id, abi_info, method_type, contract_type, create_time
                      , modify_time)
VALUES ('0x3a67288f', 0,
        '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"userAddr","type":"address"}],"name":"revokeManager","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- guomi
INSERT INTO tb_method ( method_id, group_id, abi_info, method_type, contract_type, create_time
                      , modify_time)
VALUES ('0x59a48b65', 0,
        '{"constant":true,"inputs":[{"name":"","type":"string"}],"name":"openTable","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method ( method_id, group_id, abi_info, method_type, contract_type, create_time
                      , modify_time)
VALUES ('0xd010d23c', 0,
        '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"user","type":"address"}],"name":"grantWrite","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method ( method_id, group_id, abi_info, method_type, contract_type, create_time
                      , modify_time)
VALUES ('0xdf12fe78', 0,
        '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"user","type":"address"}],"name":"revokeWrite","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method ( method_id, group_id, abi_info, method_type, contract_type, create_time
                      , modify_time)
VALUES ('0x00c77684', 0,
        '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"userAddr","type":"address"}],"name":"revokeManager","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());

-- 修改表 --
-- TODO 二进制字段 bytea 为变长 无需修改
-- ALTER TABLE tb_contract MODIFY COLUMN contract_path varchar (128) binary NOT NULL;
-- ALTER TABLE tb_cns MODIFY COLUMN contract_path varchar (128) binary DEFAULT NULL;
-- ALTER TABLE tb_contract_path MODIFY COLUMN contract_path varchar (128) binary NOT NULL;
-- TODO 这个索引被 tb_user 表占用,无需删除.
-- ALTER TABLE tb_abi
--     DROP INDEX unique_name;

-- SET FOREIGN_KEY_CHECKS = 1;
