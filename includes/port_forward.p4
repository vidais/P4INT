/*
 * Copyright 2020-2021 PSNC, FBK
 *
 * Author: Damian Parniewicz, Damu Ding
 *
 * Created in the GN4-3 project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
control PortForward(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action send(bit<9> port) {
        //standard_metadata.egress_port = port;
        standard_metadata.egress_spec = port;
    }

    table tb_port_forward {
        actions = {
            send;
        }
        key = {
            standard_metadata.egress_port : exact;
        }
        size = 31;
    }

    apply {
        tb_port_forward.apply();
    }
}