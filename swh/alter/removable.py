# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""
This module implements the marking stage of the
:ref:`removal algorithm <alter_removal_algorithm>`.
"""

from enum import Enum, auto
import hashlib
from itertools import chain
import logging
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set

from igraph import Vertex

from swh.graph.http_client import GraphArgumentException, RemoteGraphClient
from swh.model.swhids import ExtendedObjectType as ObjectType
from swh.model.swhids import ExtendedSWHID
from swh.storage.interface import StorageInterface

from .inventory import InventorySubgraph
from .progressbar import ProgressBar, ProgressBarInit, no_progressbar
from .subgraph import Subgraph
from .utils import iter_swhids_grouped_by_type

logger = logging.getLogger(__name__)

NEVER_REMOVABLE: Set[ExtendedSWHID] = {
    ExtendedSWHID.from_string(swhid)
    for swhid in [
        # Empty content
        "swh:1:cnt:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
        # 1-byte contents
        "swh:1:cnt:0015308348bf55e30efa51f842ae48361a8d0bdb",
        "swh:1:cnt:0022a3ee843f9c3d983aaf4f255cefeafe2859a0",
        "swh:1:cnt:009080e8e0bf834027bd7a55094c2e09e868e67b",
        "swh:1:cnt:00b15c0a321af2492988194cb33b5f55b2ae8332",
        "swh:1:cnt:013d565bb4055b02b0853816a9f6c69d1478f3f3",
        "swh:1:cnt:02358d2358658574ba0767140caa4216ee7ea5bf",
        "swh:1:cnt:02691e3522cd51ad600902451eace5b54cce5018",
        "swh:1:cnt:04f7b5be6987d303c24a0aa2761207922f6bbf66",
        "swh:1:cnt:050ac90ecbd9ce5a88212058fad711b4231d104d",
        "swh:1:cnt:0519ecba6ea913e21689ec692e81e9e4973fbf73",
        "swh:1:cnt:05de4782e137f9a25e63fa2cac3c94ba218dc69d",
        "swh:1:cnt:05fdf94240ddb18dae9aa42f4d35d6099b93bc7e",
        "swh:1:cnt:07e2dac48ff656acc86895efc33941223195b371",
        "swh:1:cnt:080c324fec6abbac88b03ca1298b71b6d69f9de1",
        "swh:1:cnt:0817502b11d3d776cac53346c03336e236cfa665",
        "swh:1:cnt:083b700b23248d19fdf63d7501b802a9556dcd90",
        "swh:1:cnt:08b9811c98f0d90dbacc006ddcd80c5945b9ea55",
        "swh:1:cnt:08e5b85ed7d87899de10f8cda7f7d94c8541a8fd",
        "swh:1:cnt:0901ffdd0da48f1648b19e1833a4e2d9b5a24fbe",
        "swh:1:cnt:0d758c9c7bc06c1e307f05d92d896aaf0a8a6d2c",
        "swh:1:cnt:0f0f3e3b1ff2bc6722afc3e3812e6b782683896f",
        "swh:1:cnt:0f137124110a2cc080e70794f98f7c8e5fd87e75",
        "swh:1:cnt:0fe2fa50e8e79f56b23267be86bde68d6f86195b",
        "swh:1:cnt:12183abc9e3e34700451537045dd9c0b6db609f3",
        "swh:1:cnt:127620c78a33b65b9b1b3f40843e7236e50e8c6c",
        "swh:1:cnt:13c603768561c8efce4659491508b21865b635f8",
        "swh:1:cnt:147efaa6d93d25dca26529dc3940f2079c330880",
        "swh:1:cnt:148a7b00c1946b6655f525fcfbd1dade6cf0dd2e",
        "swh:1:cnt:14ceb3ee12a1980c71ee530968609e528159164e",
        "swh:1:cnt:152f9ed5aa2d840c4a115d34ac0271262ca416ef",
        "swh:1:cnt:1578e7b311acfb74c9dffb8a38edfa9a4171fdcc",
        "swh:1:cnt:16e0e90df089debac429ebcae3cd8ea4b886aa62",
        "swh:1:cnt:16e45d390712388410556b522c74a11637716844",
        "swh:1:cnt:195ee38114e6c3445dd9b88f3dd21cc184662067",
        "swh:1:cnt:1987bbd3f002a19fb61286144bb143274285f89d",
        "swh:1:cnt:1bbf238cfb853e6bc5f6f5c85118d6b850b581ff",
        "swh:1:cnt:1bd8bf6057312efa3c5e9d7e11fdacd688640b6c",
        "swh:1:cnt:1c8a0e7976207fb9f03ed7e260950b62b8b9d396",
        "swh:1:cnt:1d2f01491f783c8c7f0917cc68526c6307d80e39",
        "swh:1:cnt:1d79949788956cdcd635f20bc67797e63beb8df9",
        "swh:1:cnt:1d8c7673ef786c5ff5e3b3defd0040af843bbc95",
        "swh:1:cnt:1db515f9a1604d126df3ed98ffa4cc5a844b96a2",
        "swh:1:cnt:1de00ecd4fc96b12f0281d2a802ff1ecdf76256a",
        "swh:1:cnt:2105af1f86eb44a91698fd33caccf5e105b36f9e",
        "swh:1:cnt:22aac29bb31be88e6db5e2f285243c3ab0c921dc",
        "swh:1:cnt:22ded55aa2c14af167996451c06c190f270e78a9",
        "swh:1:cnt:23fa7d31a729cb3b60694cf15e906aee5823b96f",
        "swh:1:cnt:24de910c13bb1e60fc5ec37a1058d356b1f2fa4d",
        "swh:1:cnt:25cb955ba23571f6fefd57cecf5f67454210bbc8",
        "swh:1:cnt:265ee26ceb272945f7c08a8f37c79bc6c55bb4d8",
        "swh:1:cnt:2725bca0006db42c8ee38c15dfa290bbe57f9a94",
        "swh:1:cnt:27f1d22a655c42c5a5fc9ffd583789950da11fc8",
        "swh:1:cnt:2882b1818ef42e381f47427af8f2cf8dc2337e10",
        "swh:1:cnt:2a2a526d8c3f95e6b1c615a3e056806cbf8cc7a3",
        "swh:1:cnt:2b8e128b91d3f449a15bf506aa87126c40bc68d8",
        "swh:1:cnt:2e65efe2a145dda7ee51d1741299f848e5bf752e",
        "swh:1:cnt:2f259b79aa7e263f5829bb6e98096e7ec976d998",
        "swh:1:cnt:2f94675b7cc5772325e379fc48538156958bab62",
        "swh:1:cnt:301160a93062df23030a69f4b5e4d9bf71866ee9",
        "swh:1:cnt:301792a3a0f42258c745f18acbbcc5dcf0286be0",
        "swh:1:cnt:303e398c82e88040b372475614e4fe2888bcbe56",
        "swh:1:cnt:31f442a2f86c480aa94912d5c2ead0b70426e2fb",
        "swh:1:cnt:32f64f4d836716819dc5fa9a1e09a29b428881df",
        "swh:1:cnt:3410062ba67c5ed59b854387a8bc0ec012479368",
        "swh:1:cnt:34164076ecce82a01452f1c2979bac48c45e3afb",
        "swh:1:cnt:35ec3b9d7586b46c0fd3450ba21e30ef666cfcd6",
        "swh:1:cnt:3818ded670e4fc852dd922ff3299908102068e42",
        "swh:1:cnt:384f448f22e6a76511824c5395336eb84e13959f",
        "swh:1:cnt:395831125cab5cd356b62c6d4883454a8a511a28",
        "swh:1:cnt:39e8d66025179ed66f49e6d776fe9c4468d14eff",
        "swh:1:cnt:3a6e607aa5ab4cb455d463049b8c5d7ed0d6e4b8",
        "swh:1:cnt:3cf20d57b0b8258463711cedd592007b0b5cdfe8",
        "swh:1:cnt:3ea63c2ccdc40ee588966429fe688570ccb02c7c",
        "swh:1:cnt:3f1695f161395210e9ab0e22d48014e179514e21",
        "swh:1:cnt:40a2dbb37b14d86d8da15ba799af13f013722c2a",
        "swh:1:cnt:41622b472098a6142f0225b50140189cfbd51779",
        "swh:1:cnt:4238428a9eacce28e3248da18e7847c756668e6b",
        "swh:1:cnt:4287ca8617970fa8fc025b75cb319c7032706910",
        "swh:1:cnt:4489a65003548ac3a08ee5d03b9535c7f7f7dead",
        "swh:1:cnt:449e49efc2a6de36206ab0e4f38ecfce9ec15632",
        "swh:1:cnt:45a8ca02bfc82ca6f053c14f35bc90a6382b2612",
        "swh:1:cnt:45c30f49c0daf7d28dedf8e6caf6196e5caf4a92",
        "swh:1:cnt:46df076df476712741056c452b634482efcf74d8",
        "swh:1:cnt:4977bc62c0e5eedda3a63e1250139237f32fb671",
        "swh:1:cnt:4be2460889810589fe96270d93248b528079cc7b",
        "swh:1:cnt:4d1ae35ba2c8ec712fa2a379db44ad639ca277bd",
        "swh:1:cnt:4e3bc519eef7d5a35fff67687eaee65616832e45",
        "swh:1:cnt:4f0734cbe3ae9d87287203f06e908edec7c8ed4d",
        "swh:1:cnt:4f6c4ee9d928270b4304e3abcd8d81df3e740d12",
        "swh:1:cnt:4fc3fe1ce587c1fb2acc24b2074dac4438d1b30b",
        "swh:1:cnt:500c0709ca24338426091ca19777e13a1920ebdf",
        "swh:1:cnt:501a6bbaf1e2cec78ba2c39f1bd551a43638094b",
        "swh:1:cnt:50c8be35f7782588f82895b7f1890f5fca711866",
        "swh:1:cnt:52771883833a931bf221105e2eb19fdc30a1631a",
        "swh:1:cnt:52d0524746f70b293da3def801a5823b8b9ce3a1",
        "swh:1:cnt:52e60b4495af680809173f50b2918757eb176e76",
        "swh:1:cnt:5416677bc7dab0c8bec3f5bf44d7d28b4ff73b13",
        "swh:1:cnt:54a81dcac6cfc078fbf4b74de360a4a2d9c762f5",
        "swh:1:cnt:54caf60b13678be3b856d9d9d5b1aa16b6cbe8fe",
        "swh:1:cnt:5639b6ddcf62a692b4cbd6d97d3138829c83b9e7",
        "swh:1:cnt:566d900abb9af2df549e573a5c0b8c5d7c3204fc",
        "swh:1:cnt:56a6051ca2b02b04ef92d5150c9ef600403cb1de",
        "swh:1:cnt:57814dd0025fca1ddd1e1058fa08ca9e56651f04",
        "swh:1:cnt:597a6db294cb721d184d6f12560dfa9e8a67de33",
        "swh:1:cnt:59cd9bddc043471be2a00f84e2a122af85fe8a08",
        "swh:1:cnt:5a77f05831a38ab834f5f49342e29f931e073f5a",
        "swh:1:cnt:5bd7dea14b4c665b222ff69cbb7a0496dc3b71b1",
        "swh:1:cnt:5cd813e5c5f312673ce9cf39fb832fb2d55116cc",
        "swh:1:cnt:5d33882543d5ade31a988fd3b8aef02faf12d742",
        "swh:1:cnt:60a89ed235449c0bc49f2280ca81ccc88125fff6",
        "swh:1:cnt:62f9457511f879886bb7728c986fe10b0ece6bcb",
        "swh:1:cnt:63d8dbd40c23542e740659a7168a0ce3138ea748",
        "swh:1:cnt:64845fb7679efbd24296bf0499f7386cde449f0a",
        "swh:1:cnt:675f43ab433f9bacd8574d633afe18364af6a107",
        "swh:1:cnt:67c3297611451bb352bbda488b0cd7cb2528a0d3",
        "swh:1:cnt:680fc5115355e433bf39e51c98f66ddb8e3dce22",
        "swh:1:cnt:6b10f9584314d9e7304b2c13c480fc3d01acabe9",
        "swh:1:cnt:6b2aaa7640726588bcd3d57e1de4b1315b7f315e",
        "swh:1:cnt:6bf0c97a7f84620a0bb4cf6380ec307748e043bd",
        "swh:1:cnt:6cc8370785d2e6c51b9de5ff36cda89a1a9aa2f9",
        "swh:1:cnt:6d0b7ebde95e1fbd7cc77a60d46a3468f61038cc",
        "swh:1:cnt:6d7ce64fb8c0411b6a006095186464c3a70de1be",
        "swh:1:cnt:6f4f765ed6998a016a32bf9b4c48b77219ef7f0a",
        "swh:1:cnt:7136b4c89bbca73c68a2ee0eaca246942d6fa2bb",
        "swh:1:cnt:7371f47a6f8bd23a8fa1a8b2a9479cdd76380e54",
        "swh:1:cnt:74e0f12e3246e5d0b556558359a30e0991092cdc",
        "swh:1:cnt:7813681f5b41c028345ca62a2be376bae70b7f61",
        "swh:1:cnt:7937c68fbcf7c484f2d5ce7801944416eedf0d2c",
        "swh:1:cnt:79b7e4bad2a1676d0db76503825455527b89d932",
        "swh:1:cnt:7b71c6e679738d980d5d03559d35fd88a66ee9e4",
        "swh:1:cnt:7c42345690273ab86713294ad761386871c7b708",
        "swh:1:cnt:7de85f863158583176767468e52c7cbb92996542",
        "swh:1:cnt:81750b96f9d83b395f285233d54ec0c9df9ab93d",
        "swh:1:cnt:8214d0ee079917c29e57d16e764fc46de8fb50bf",
        "swh:1:cnt:825026bf2f91b30f020cdba8326485cc600d8a4d",
        "swh:1:cnt:835a5816354544643aeb095a3de6ae8c43136c6d",
        "swh:1:cnt:84f8fe2f54c9b5bf32ddbea402b6ae4af382fa76",
        "swh:1:cnt:851c75cc5e74cf97d145360755d116d2409881f2",
        "swh:1:cnt:866ad4749eb52020cf6b9791205db4af53d337e1",
        "swh:1:cnt:883ad6e8ef9a7392b45f6fc9e7d53c88f502388b",
        "swh:1:cnt:8a908eccd273b758a246975d2eaf96968ceb330d",
        "swh:1:cnt:8ac2eb508956928faf94cbca788daa7b2aeb7735",
        "swh:1:cnt:8b0e2fb7fa3d187b31a6970199816db30d79e8df",
        "swh:1:cnt:8b1296cad20a66969613992eb9e0eb493a1b21fa",
        "swh:1:cnt:8b137891791fe96927ad78e64b0aad7bded08bdc",
        "swh:1:cnt:8b43ca9ac41e863b1817ba9c2631c33ed0b95265",
        "swh:1:cnt:8c53a7f5f36f2172d12e3142124b3da1ee9321b6",
        "swh:1:cnt:8c7e5a667f1b771847fe88c01c3de34413a1b220",
        "swh:1:cnt:8cbf1afc66d01c03210c74c6c3837cf879484525",
        "swh:1:cnt:8e2f0bef135ba8e52e4110b6a5b0ebf19a528ca4",
        "swh:1:cnt:8f7462996850b690a4a2b2d5c368475744ec29fb",
        "swh:1:cnt:9280c0d31d5a7c1fd9abaaa7ffd6160759eca320",
        "swh:1:cnt:92a39f398b80310c58aa2574dd97a3e35527b73b",
        "swh:1:cnt:945c9b46d684f08ec84cb316e1dc0061e361f794",
        "swh:1:cnt:96583aabf5a13fdc518899efd0c92c41da28eb2f",
        "swh:1:cnt:96d80cd6c4e7158dbebd0849f4fb7ce513e5828c",
        "swh:1:cnt:9b26e9b102ab2917db3dc1f6ced91065a38205a8",
        "swh:1:cnt:9beacf8e6f5cd023ac57d0b97432c7cc250c6b96",
        "swh:1:cnt:9c95a6ba6af7377402d44dc60243769a4c604364",
        "swh:1:cnt:9cbe6ea56f225388ae614c419249bfc6d734cc30",
        "swh:1:cnt:9d3cd6889873b86c6796ac62f33b7c8d57d44bc0",
        "swh:1:cnt:9d68933c44f13985b9eb19159da6eb3ff0e574bf",
        "swh:1:cnt:9de294132dec5e172c3245f7453b48ddfd1b2006",
        "swh:1:cnt:9e99dd5ec98fdb081b58e76344a05122e25dcb94",
        "swh:1:cnt:9fb75b8d4f4c7faa7ba59d138746231ada07c7b0",
        "swh:1:cnt:9fc8861321f106d71a197c0e06655b10242f82a1",
        "swh:1:cnt:a2344cdfa5b899d869dde30985646273655014d0",
        "swh:1:cnt:a3871d4508259dc2e3eae0be6fc69d1d3daf0a35",
        "swh:1:cnt:a4a063a1573238b224841eb6556061a7ec1f822e",
        "swh:1:cnt:a4ceb359eba9f667d23d07784d7208f8188fcbbe",
        "swh:1:cnt:a5a3498915908e0e03f66cd28e52b9fc87d1c3d5",
        "swh:1:cnt:a8e73b1b7c227edf8c112fc273e9929b88301b13",
        "swh:1:cnt:aa91d5c03e2002a1057f8075f67a189aeaae3f2b",
        "swh:1:cnt:ac044e5e4649cd149e3d0cf9d23720d299288a1e",
        "swh:1:cnt:ad2823b48f78a0667817300ddcac54c2f6c385e9",
        "swh:1:cnt:ae9780bc629ea3cb16fadbba91e393318af71465",
        "swh:1:cnt:afb09b4e6d0e92bd13951b4f9d3ded90c8c4e89a",
        "swh:1:cnt:b0b2b1c8ddb2dd9e025526d2ea88d82854de6be8",
        "swh:1:cnt:b15531f5dd7f917929f0331f7f65018f9c7c25cc",
        "swh:1:cnt:b1d81e79354c904c6cd8bf5bf91f4c9c9502f381",
        "swh:1:cnt:b4158c40d2962b0ec90bde1019290ae984adf2a3",
        "swh:1:cnt:b516b2c489f1fefd53b4a1905bf37480a8eb056d",
        "swh:1:cnt:b54b8e79bb8d039944e1adf71c97c3c74676ab73",
        "swh:1:cnt:b59c5945f9f68d5e239c35ed33100dd24b27b800",
        "swh:1:cnt:b66e5558e5a67ea386d6f6fea028555b8009d0f9",
        "swh:1:cnt:b7d5379f9e3bb741760e46cf87c89b081f8f44d9",
        "swh:1:cnt:b8635bcf0d86ea51ce65da503c779e72262c0c9e",
        "swh:1:cnt:b9798c2427e725d88f22a1fe75cd165046f614f7",
        "swh:1:cnt:baf72b1da3ee845c0543fe0acf4e02e1a031f397",
        "swh:1:cnt:bb79ec2de59197fe11eeb60d312673a87c1b8932",
        "swh:1:cnt:bb7d13c5e9acc98633147acb5e2e5cd2dda09978",
        "swh:1:cnt:bd0fd35942234660f0c30ba251abaa81eda68fd1",
        "swh:1:cnt:bd97d75340e460bdddedbc17115518f47aa5ba93",
        "swh:1:cnt:be54354a9433a1e798cf17a5cddffbf581e3afa2",
        "swh:1:cnt:bf0d87ab1b2b0ec1a11a3973d2845b42413d9767",
        "swh:1:cnt:c137216fe167556782049b618443432e9409fa53",
        "swh:1:cnt:c1b0730e0133447badcfd47fd144e254807b06e1",
        "swh:1:cnt:c227083464fb9af8955c90d2924774ee50abb547",
        "swh:1:cnt:c2fb4f3370c4e65a8a889f93628d0dd0d0d02726",
        "swh:1:cnt:c30d0581bfa3e1d73eb6a5efbe638c72911dadb7",
        "swh:1:cnt:c32b65a02039b3e986f3b49bdd19f90ffd6e23ff",
        "swh:1:cnt:c471733217fd3bdca8cae8a713b434a3d16ea303",
        "swh:1:cnt:c59d9b6344f1af00e504ba698129f07a34bbed8d",
        "swh:1:cnt:c5fa78456dbde5c0ffa05377925131501c0c794d",
        "swh:1:cnt:c7930257dfef505fd996e1d6f22f2f35149990d0",
        "swh:1:cnt:c96ab3cc70e72f99ab51e3bdab9465fe177c7923",
        "swh:1:cnt:c9cdc63b07017d57efbf45789ceaecc069064a8b",
        "swh:1:cnt:caad5337178380d33d72638694c823b03963b7da",
        "swh:1:cnt:cd571f464ed47d4549f59166841c6a041921342b",
        "swh:1:cnt:ce542efaa5124a0437f0c4db329d7ec4b7ba70a7",
        "swh:1:cnt:d133603777a89a23bce43ec32130942a3c93ba5c",
        "swh:1:cnt:d426ba8a32b9ab2d8f994b193c0302ea46d5e5c3",
        "swh:1:cnt:d50394efdf1c93a17379ff5799d1922b2d436026",
        "swh:1:cnt:d6c11f4cd0a101d19c54e9c378526bdf21988732",
        "swh:1:cnt:d77740a55759db09434d496f10527e0560ee590d",
        "swh:1:cnt:d8263ee9860594d2806b0dfd1bfd17528b0ba2a4",
        "swh:1:cnt:dd67376917e5edd850e1db02049d5c6115462d8d",
        "swh:1:cnt:ddf3b06abfe0500f89028d1b1304c57169da8c87",
        "swh:1:cnt:df3d21358f562c835826070e8ef31e0de97e13a4",
        "swh:1:cnt:e0074173a81d3825f14fe83d3aefc03d51476f00",
        "swh:1:cnt:e0aa8a9ce7243aa018b70b3839d567b14fcf01e0",
        "swh:1:cnt:e25f1814e51579d5f55c0f1fe0135ddb28a47f4a",
        "swh:1:cnt:e2cd95fdbf767aa5e9a1f1bd67167db4a0725d5d",
        "swh:1:cnt:e440e5c842586965a7fb77deda2eca68612b1f53",
        "swh:1:cnt:e49435269d332947aed299a315268e347fb29e7e",
        "swh:1:cnt:e515dc1cf2373da83cc4b248c392c241e4ea2afc",
        "swh:1:cnt:e5db411da00fcba56fe620bad5192fc6a7b1325b",
        "swh:1:cnt:e7754cae5adecf1f21102527fbdeae39280f8e24",
        "swh:1:cnt:e7a5832a436197d3bdc6c6d879a732c627497b0d",
        "swh:1:cnt:e8a0f87653d8b78789cb183ba19f357c636ad33f",
        "swh:1:cnt:ea0c8a85cb7293feae2c9e151d1d395be59b61fa",
        "swh:1:cnt:ea9ed43d2b2445bf0ef9bc4e146f93f329d90109",
        "swh:1:cnt:ec5fd4221a9dbb645852c59f2a455671b4f2bfd0",
        "swh:1:cnt:eda5949cbef3c59679d61a78aa0654d43c3f06fa",
        "swh:1:cnt:eea1bf0c31f3d493509fa1ddd9d25c734eb35277",
        "swh:1:cnt:eec1a4233f3f92568aa3ede33cb1f4ddb6dcc251",
        "swh:1:cnt:ef073cc45ccc66c921adc7ccc6221e38aa54ae17",
        "swh:1:cnt:ef6080906700f3f3cdac7d60341a5de7b5da5581",
        "swh:1:cnt:ef6bce1d1d15c6721aa1c5cce64b10378dfcc844",
        "swh:1:cnt:f11c82a4cb6cc2e8f3bdf52b5cdeaad4d5bb214e",
        "swh:1:cnt:f1b38290cdf3564ec0d9a35bea05c5cb5cd5f503",
        "swh:1:cnt:f327b9acc7ffd3c3008a5363dad25358ca32f643",
        "swh:1:cnt:f3c6c3c68af484bd95bc7b7a38276c6c014d6aa3",
        "swh:1:cnt:f46d387bf94c89b81aaec9cff2ee52d1f9ab4187",
        "swh:1:cnt:f4c82dc4e83cb89b72d1713652f6cdc19ccb2aa4",
        "swh:1:cnt:f59ec20aabf5842d237244ece8c81ab184faeac1",
        "swh:1:cnt:f76dd238ade08917e6712764a16a22005a50573d",
        "swh:1:cnt:f7a8cadeb57c7e92cda09b565e88c21487119d8e",
        "swh:1:cnt:f7cb26f07be14f68a35431ff8ab12b69b61424a3",
        "swh:1:cnt:f8fa5a235408d5c6f2c2844e44cd98c1fa666ac8",
        "swh:1:cnt:f9825866e00f2b8cd33a9dabe1a23a9ee7b3c984",
        "swh:1:cnt:fa7af8bf5fdd704f73beb3adc5612682a98e1af5",
        "swh:1:cnt:fc2b5693e00bdbea3f74ac60459b1df43c295356",
        "swh:1:cnt:fe1990c57a840e97c1075904f9e96daed2e65030",
        "swh:1:cnt:ff30235f076b3fde71fba6ceafa0f510e0006261",
        "swh:1:cnt:ff7dbb100623d2c1f447485012e8de229821cc84",
        # MIT License
        "swh:1:cnt:654d0bfe943437d43242325b1fbcff5f400d84ee",
        "swh:1:cnt:e7af2f77107d73046421ef56c4684cbfdd3c1e89",
        "swh:1:cnt:ee27ba4b4412b0e4a05af5e3d8a005bc6681fdf3",
        # GPLv2
        "swh:1:cnt:d159169d1050894d3ea3b98e1c965c4058208fe1",
        "swh:1:cnt:d511905c1647a1e311e8b20d5930a37a9c2531cd",
        "swh:1:cnt:d60c31a97a544b53039088d14fe9114583c0efc3",
        # GPLv3
        "swh:1:cnt:65c5ca88a67c30becee01c5a8816d964b03862f9",
        "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
        "swh:1:cnt:9cecc1d4669ee8af2ca727a5d8cde10cd8b2d7cc",
        "swh:1:cnt:f288702d2fa16d3cdf0035b15a9fcbc552cd88e7",
        # AGPLv3
        "swh:1:cnt:dba13ed2ddf783ee8118c6a581dbf75305f816a3",
        # Apache License 2.0
        "swh:1:cnt:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64",
        "swh:1:cnt:8dada3edaf50dbc082c9a125058f25def75e625a",
        "swh:1:cnt:d645695673349e3947e8e5ae42332d0ac3164cd7",
        # ISC License
        "swh:1:cnt:19129e315fe593965a2fdd50ec0d1253bcbd2ece",
        # Create React App .gitignore
        "swh:1:cnt:4d29575de80483b005c29bfcac5061cd2f45313e",
        # React logo
        "swh:1:cnt:6b60c1042f58d9fabb75485aa3624dddcf633b5c",
        # VisualStudio default .gitattributes
        "swh:1:cnt:1ff0c423042b46cb1d617b81efb715defbe8054d",
        # Very common .gitattributes
        "swh:1:cnt:dfe0770424b2a19faf507a501ebfc23be8f54e7b",
        # Empty directory
        "swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        # Directory with empty .keep
        "swh:1:dir:29a422c19251aeaeb907175e9b3219a9bed6c616",
        # Directory with empty .gitkeep
        "swh:1:dir:d564d0bc3dd917926892c55e3706cc116d5b165e",
        # Directory with empty .gitignore
        "swh:1:dir:82e3a754b6a0fcb238b03c0e47d05219fbf9cf89",
        # Directory with empty __init__.py
        "swh:1:dir:9d1dcfdaf1a6857c5f83dc27019c7600e1ffaff8",
        # Empty snapshot
        "swh:1:snp:1a8893e6a86f444e8be8e7bda6cb34fb1735a00e",
    ]
}


class MarkingState(Enum):
    """Represents the different state of vertices while the marking algorithm is on-going.

    All vertices start UNMARKED. After examination of their inbound references, they are
    either marked as REMOVABLE or UNREMOVABLE.

    :meta private:
    """

    UNMARKED = auto()
    REMOVABLE = auto()
    UNREMOVABLE = auto()


class RemovableSubgraph(Subgraph):
    """A class representing the subgraph of objects that can be safely removed
    from the archive

    This subgraph should only be created from an :py:class:`InventorySubgraph`
    using :py:meth:`from_inventory_subgraph`. No new vertices or edges can be
    added at this point.

    Getting the list of SWHID that can be removed is done by using
    py:meth:`removable_swhids`.

    After marking happened, this subgraph will contain all candidates until
    :py:meth:`delete_unremovable` is called.
    """

    def __init__(self, *args, **kwargs):
        """ """
        super().__init__(*args, **kwargs)
        self["name"] = "Removable"
        self.vs["state"] = MarkingState.UNMARKED

    @classmethod
    def from_inventory_subgraph(cls, subgraph: InventorySubgraph):
        return cls.copy(subgraph)

    def add_vertex(self, name: str, **kwargs):
        """Not available for RemovableSubgraph.

        :meta private:"""
        raise NotImplementedError("No new vertex should be added at this stage.")

    def add_edge(self, src: Vertex, dst: Vertex, skip_duplicates=False, **kwargs):
        """Not available for RemovableSubgraph.

        :meta private:"""
        raise NotImplementedError("No new edge should be added at this stage.")

    def delete_unremovable(self):
        """Delete all vertices for unremovable objects from this subgraph."""

        self.delete_vertices(self.vs.select(state_eq=MarkingState.UNREMOVABLE))

    def removable_swhids(self) -> List[ExtendedSWHID]:
        """Returns a list of SWHIDs that can safely be removed from the archive."""

        return [
            v["swhid"] for v in self.select_ordered(state_eq=MarkingState.REMOVABLE)
        ]

    def dot_node_attributes(self, v: Vertex) -> List[str]:
        """Get a list of attributes in DOT format for the given vertex.

        On top of default attributes, color the background of each node if
        they can be removed or not.

        :meta private:
        """
        attrs = super().dot_node_attributes(v)
        # Unset the shape so we can better spot ExtendedSWHID that can be removed
        if v["state"] == MarkingState.UNMARKED:
            attrs.append('style="filled,dotted"')
        elif v["state"] == MarkingState.UNREMOVABLE:
            attrs.append("fillcolor=white")
        else:
            attrs.append("fillcolor=red")
        return attrs


class Marker:
    """A class encapsulating our algorithm marking nodes as removable or not.

    :meta private:
    """

    def __init__(
        self,
        storage: StorageInterface,
        graph_client: RemoteGraphClient,
        subgraph: RemovableSubgraph,
        progressbar: ProgressBar[Vertex],
    ):
        self._storage = storage
        self._graph_client = graph_client
        self._subgraph = subgraph
        self._progressbar = progressbar

    @property
    def subgraph(self):
        return self._subgraph

    def has_unknown_inbound_edges(self, vertex: Vertex):
        # Origins never have any inbound edges
        if vertex["swhid"].object_type == ObjectType.ORIGIN:
            return False
        # We use a set of str as an optimization because
        # swh.graph API will return SWHIDs as str
        known_predecessors = {str(pred["swhid"]) for pred in vertex.predecessors()}
        # We only need to find one extra edge from the ones we already know
        search_limit = len(known_predecessors) + 1
        for pred in chain(
            self.inbound_edges_from_graph(vertex, search_limit),
            self.inbound_edges_from_storage(vertex, search_limit),
        ):
            # Removing a revision used as a submodule should be possible.
            # (We do not care that it will make submodule users miss part
            # of their source code.)
            # We use string matching here because the graph API returns
            # str objects and not ExtendedSWHID objects.
            if vertex["swhid"].object_type == ObjectType.REVISION and pred.startswith(
                "swh:1:dir:"
            ):
                logger.info(
                    "Skipping predecessor %s of %s as it's a submodule",
                    pred,
                    vertex["swhid"],
                )
                return False
            if pred not in known_predecessors:
                logger.debug(
                    "%s has an extra predecessor (%s), skipping removal",
                    vertex["swhid"],
                    pred,
                )
                return True
        return False

    def inbound_edges_from_graph(
        self, vertex: Vertex, search_limit: int
    ) -> Iterator[str]:
        # We need to check if the object still exists in storage, as it
        # might have been removed since the graph was exported. We
        # work on objects grouped by object types for efficiency.

        try:
            swhids_from_graph = [
                ExtendedSWHID.from_string(str)
                for str in self._graph_client.neighbors(
                    str(vertex["swhid"]),
                    direction="backward",
                    max_matching_nodes=search_limit,
                )
            ]

            def collector(swhids: Iterable[ExtendedSWHID]) -> Set[bytes]:
                return {swhid.object_id for swhid in swhids}

            handlers: Dict[ObjectType, Callable[[set[bytes]], Iterable[str]]] = {
                ObjectType.CONTENT: self._filter_missing_contents,
                ObjectType.DIRECTORY: self._filter_missing_directories,
                ObjectType.REVISION: self._filter_missing_revisions,
                ObjectType.RELEASE: self._filter_missing_releases,
                ObjectType.SNAPSHOT: self._filter_missing_snapshots,
                ObjectType.ORIGIN: self._filter_missing_origins,
            }
            swhids_filtered_by_storage = list(
                iter_swhids_grouped_by_type(
                    swhids_from_graph, handlers=handlers, collector=collector
                )
            )
            filtered_count = len(swhids_from_graph) - len(swhids_filtered_by_storage)
            if len(swhids_from_graph) >= search_limit and filtered_count > 0:
                yield from self.inbound_edges_from_graph(
                    vertex, search_limit + filtered_count
                )
            else:
                yield from swhids_filtered_by_storage
        except GraphArgumentException:
            yield from ()

    def _filter_missing_contents(
        self, requested_object_ids: Set[bytes]
    ) -> Iterable[str]:
        missing_object_ids = set(
            self._storage.content_missing_per_sha1_git(list(requested_object_ids))
        )
        yield from (
            str(ExtendedSWHID(object_type=ObjectType.CONTENT, object_id=object_id))
            for object_id in requested_object_ids - missing_object_ids
        )

    def _filter_missing_directories(
        self, requested_object_ids: Set[bytes]
    ) -> Iterable[str]:
        missing_object_ids = set(
            self._storage.directory_missing(list(requested_object_ids))
        )
        yield from (
            str(ExtendedSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id))
            for object_id in requested_object_ids - missing_object_ids
        )

    def _filter_missing_revisions(
        self, requested_object_ids: Set[bytes]
    ) -> Iterable[str]:
        missing_object_ids = set(
            self._storage.revision_missing(list(requested_object_ids))
        )
        yield from (
            str(ExtendedSWHID(object_type=ObjectType.REVISION, object_id=object_id))
            for object_id in requested_object_ids - missing_object_ids
        )

    def _filter_missing_releases(
        self, requested_object_ids: Set[bytes]
    ) -> Iterable[str]:
        missing_object_ids = set(
            self._storage.release_missing(list(requested_object_ids))
        )
        yield from (
            str(ExtendedSWHID(object_type=ObjectType.RELEASE, object_id=object_id))
            for object_id in requested_object_ids - missing_object_ids
        )

    def _filter_missing_snapshots(
        self, requested_object_ids: Set[bytes]
    ) -> Iterable[str]:
        missing_object_ids = set(
            self._storage.snapshot_missing(list(requested_object_ids))
        )
        yield from (
            str(ExtendedSWHID(object_type=ObjectType.SNAPSHOT, object_id=object_id))
            for object_id in requested_object_ids - missing_object_ids
        )

    def _filter_missing_origins(
        self, requested_object_ids: Set[bytes]
    ) -> Iterable[str]:
        # XXX: We should add a better method in swh.storage
        yield from (
            f"swh:1:ori:{hashlib.sha1(d['url'].encode('utf-8')).hexdigest()}"
            for d in self._storage.origin_get_by_sha1(list(requested_object_ids))
            if d is not None
        )

    def inbound_edges_from_storage(
        self, vertex: Vertex, search_limit: int
    ) -> Iterator[str]:
        yield from map(
            str,
            self._storage.object_find_recent_references(
                vertex["swhid"], limit=search_limit
            ),
        )

    def mark_candidates(self):
        for index, vid in enumerate(self._subgraph.topological_sorting()):
            vertex = self._subgraph.vs[vid]
            assert all(
                pred["state"] != MarkingState.UNMARKED for pred in vertex.predecessors()
            ), "topological sort broken: one predecessor is still in unmarked state"

            self._progressbar.update(1)

            if vertex["swhid"] in NEVER_REMOVABLE:
                vertex["state"] = MarkingState.UNREMOVABLE
                continue

            # If any predecessor is unremovable, this makes this object unremovable too
            if any(
                pred["state"] == MarkingState.UNREMOVABLE
                for pred in vertex.predecessors()
            ):
                vertex["state"] = MarkingState.UNREMOVABLE
                continue
            vertex["state"] = (
                MarkingState.UNREMOVABLE
                if self.has_unknown_inbound_edges(vertex)
                else MarkingState.REMOVABLE
            )


def mark_removable(
    storage: StorageInterface,
    graph_client: RemoteGraphClient,
    inventory_subgraph: InventorySubgraph,
    progressbar: Optional[ProgressBarInit] = None,
) -> RemovableSubgraph:
    """Find which candidates can be safely removed from the archive.

    Using the previously populated ``inventory_subgraph``, query the given
    ``storage`` and ``graph_client`` to assess inbound references for each
    candidate and see which one can be safely removed from the archive.
    """
    subgraph = RemovableSubgraph.from_inventory_subgraph(inventory_subgraph)
    progressbar_init: ProgressBarInit = progressbar or no_progressbar
    bar: ProgressBar[int]
    with progressbar_init(
        length=len(subgraph.vs),
        label="Determining which objects can be safely removed…",
    ) as bar:
        marker = Marker(storage, graph_client, subgraph, bar)
        marker.mark_candidates()
    return marker.subgraph
