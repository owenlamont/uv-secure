from pathlib import Path
from textwrap import dedent

from anyio import Path as APath
import pytest

from uv_secure.package_info import (
    Dependency,
    parse_requirements_txt_file,
    parse_uv_lock_file,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requirements_txt_contents", "expected_dependencies"),
    [
        pytest.param("", [], id="No dependencies"),
        pytest.param(
            """
            # This file was autogenerated by uv via the following command:
            #    uv pip compile requirements.in -o requirements.txt
            humanize==4.12.0
                # via -r requirements.in
            """,
            [Dependency(name="humanize", version="4.12.0", first_order=True)],
            id="First order from requirements.in",
        ),
        pytest.param(
            """
            # This file was autogenerated by uv via the following command:
            #    uv pip compile requirements.in -o requirements.txt
            anyio==4.8.0
                # via httpx
            certifi==2025.1.31
                # via
                #   httpcore
                #   httpx
            colorama==0.4.6
                # via pytest
            h11==0.14.0
                # via httpcore
            httpcore==1.0.7
                # via httpx
            httpx==0.28.1
                # via
                #   -r requirements.in
                #   pytest-httpx
            humanize==4.12.0
                # via -r requirements.in
            idna==3.10
                # via
                #   anyio
                #   httpx
            iniconfig==2.0.0
                # via pytest
            packaging==24.2
                # via pytest
            pluggy==1.5.0
                # via pytest
            pytest==8.3.4
                # via pytest-httpx
            pytest-httpx==0.35.0
                # via -r requirements.in
            sniffio==1.3.1
                # via anyio
            """,
            [
                Dependency(name="anyio", version="4.8.0", first_order=False),
                Dependency(name="certifi", version="2025.1.31", first_order=False),
                Dependency(name="colorama", version="0.4.6", first_order=False),
                Dependency(name="h11", version="0.14.0", first_order=False),
                Dependency(name="httpcore", version="1.0.7", first_order=False),
                Dependency(name="httpx", version="0.28.1", first_order=True),
                Dependency(name="humanize", version="4.12.0", first_order=True),
                Dependency(name="idna", version="3.10", first_order=False),
                Dependency(name="iniconfig", version="2.0.0", first_order=False),
                Dependency(name="packaging", version="24.2", first_order=False),
                Dependency(name="pluggy", version="1.5.0", first_order=False),
                Dependency(name="pytest", version="8.3.4", first_order=False),
                Dependency(name="pytest-httpx", version="0.35.0", first_order=True),
                Dependency(name="sniffio", version="1.3.1", first_order=False),
            ],
            id="First order and transitive dependencies from requirements.in",
        ),
        pytest.param(
            """
            # This file was autogenerated by uv via the following command:
            #    uv pip compile pyproject.toml --extra dev -o requirements.txt
            humanize==4.12.0
                # via test-uv-lock (pyproject.toml)
            """,
            [Dependency(name="humanize", version="4.12.0", first_order=True)],
            id="First order from pyproject.toml",
        ),
        pytest.param(
            """
            # This file was autogenerated by uv via the following command:
            #    uv pip compile pyproject.toml --extra dev -o requirements.txt
            anyio==4.8.0
                # via httpx
            certifi==2025.1.31
                # via
                #   httpcore
                #   httpx
            colorama==0.4.6
                # via pytest
            h11==0.14.0
                # via httpcore
            httpcore==1.0.7
                # via httpx
            httpx==0.28.1
                # via
                #   test-uv-lock (pyproject.toml)
                #   pytest-httpx
            humanize==4.12.0
                # via test-uv-lock (pyproject.toml)
            idna==3.10
                # via
                #   anyio
                #   httpx
            iniconfig==2.0.0
                # via pytest
            packaging==24.2
                # via pytest
            pluggy==1.5.0
                # via pytest
            pytest==8.3.4
                # via pytest-httpx
            pytest-httpx==0.35.0
                # via test-uv-lock (pyproject.toml)
            sniffio==1.3.1
                # via anyio
            """,
            [
                Dependency(name="anyio", version="4.8.0", first_order=False),
                Dependency(name="certifi", version="2025.1.31", first_order=False),
                Dependency(name="colorama", version="0.4.6", first_order=False),
                Dependency(name="h11", version="0.14.0", first_order=False),
                Dependency(name="httpcore", version="1.0.7", first_order=False),
                Dependency(name="httpx", version="0.28.1", first_order=True),
                Dependency(name="humanize", version="4.12.0", first_order=True),
                Dependency(name="idna", version="3.10", first_order=False),
                Dependency(name="iniconfig", version="2.0.0", first_order=False),
                Dependency(name="packaging", version="24.2", first_order=False),
                Dependency(name="pluggy", version="1.5.0", first_order=False),
                Dependency(name="pytest", version="8.3.4", first_order=False),
                Dependency(name="pytest-httpx", version="0.35.0", first_order=True),
                Dependency(name="sniffio", version="1.3.1", first_order=False),
            ],
            id="First order and transitive dependencies from pyproject.toml",
        ),
    ],
)
async def test_parse_requirements_txt_file(
    tmp_path: Path,
    requirements_txt_contents: str,
    expected_dependencies: list[Dependency],
) -> None:
    requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_path.write_text(dedent(requirements_txt_contents).strip())
    dependencies = await parse_requirements_txt_file(APath(requirements_txt_path))
    assert dependencies == expected_dependencies


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("uv_lock_contents", "expected_dependencies"),
    [
        pytest.param(
            """
            version = 1
            revision = 1
            requires-python = ">=3.13"

            [[package]]
            name = "test-uv-lock"
            version = "0.1.0"
            source = { virtual = "." }

            [package.metadata]

            [package.metadata.requires-dev]
            dev = []
            """,
            [],
            id="No dependencies - app uv.lock file",
        ),
        pytest.param(
            """
            version = 1
            revision = 1
            requires-python = ">=3.13"

            [[package]]
            name = "humanize"
            version = "4.12.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/38/ff/9f38de04e15bd53f5b64d38e6b9f21357d7b3edee7e398d05aaf407dbdfe/humanize-4.12.0.tar.gz", hash = "sha256:87ff7b43591370b12a1d103c9405849d911d4b039ed22d80b718b62c76eec8a3", size = 80785 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/d5/6b/09e54be6cc58913fd991728b9b8f959b58ade87a2a7684318c3e90e5f1dc/humanize-4.12.0-py3-none-any.whl", hash = "sha256:106a7436a2d545d742c147c469716b3a08424aa143a82103630147c489a89f48", size = 127401 },
            ]

            [[package]]
            name = "test-uv-lock"
            version = "0.1.0"
            source = { virtual = "." }
            dependencies = [
                { name = "humanize" },
            ]

            [package.metadata]
            requires-dist = [{ name = "humanize", specifier = ">=4.12.0" }]

            [package.metadata.requires-dev]
            dev = []
            """,
            [Dependency(name="humanize", version="4.12.0", first_order=True)],
            id="First order dependency - app uv.lock file",
        ),
        pytest.param(
            """
            version = 1
            revision = 1
            requires-python = ">=3.13"

            [[package]]
            name = "anyio"
            version = "4.8.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "idna" },
                { name = "sniffio" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/a3/73/199a98fc2dae33535d6b8e8e6ec01f8c1d76c9adb096c6b7d64823038cde/anyio-4.8.0.tar.gz", hash = "sha256:1d9fe889df5212298c0c0723fa20479d1b94883a2df44bd3897aa91083316f7a", size = 181126 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/46/eb/e7f063ad1fec6b3178a3cd82d1a3c4de82cccf283fc42746168188e1cdd5/anyio-4.8.0-py3-none-any.whl", hash = "sha256:b5011f270ab5eb0abf13385f851315585cc37ef330dd88e27ec3d34d651fd47a", size = 96041 },
            ]

            [[package]]
            name = "certifi"
            version = "2025.1.31"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/1c/ab/c9f1e32b7b1bf505bf26f0ef697775960db7932abeb7b516de930ba2705f/certifi-2025.1.31.tar.gz", hash = "sha256:3d5da6925056f6f18f119200434a4780a94263f10d1c21d032a6f6b2baa20651", size = 167577 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/38/fc/bce832fd4fd99766c04d1ee0eead6b0ec6486fb100ae5e74c1d91292b982/certifi-2025.1.31-py3-none-any.whl", hash = "sha256:ca78db4565a652026a4db2bcdf68f2fb589ea80d0be70e03929ed730746b84fe", size = 166393 },
            ]

            [[package]]
            name = "colorama"
            version = "0.4.6"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/d8/53/6f443c9a4a8358a93a6792e2acffb9d9d5cb0a5cfd8802644b7b1c9a02e4/colorama-0.4.6.tar.gz", hash = "sha256:08695f5cb7ed6e0531a20572697297273c47b8cae5a63ffc6d6ed5c201be6e44", size = 27697 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/d1/d6/3965ed04c63042e047cb6a3e6ed1a63a35087b6a609aa3a15ed8ac56c221/colorama-0.4.6-py2.py3-none-any.whl", hash = "sha256:4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6", size = 25335 },
            ]

            [[package]]
            name = "h11"
            version = "0.14.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/f5/38/3af3d3633a34a3316095b39c8e8fb4853a28a536e55d347bd8d8e9a14b03/h11-0.14.0.tar.gz", hash = "sha256:8f19fbbe99e72420ff35c00b27a34cb9937e902a8b810e2c88300c6f0a3b699d", size = 100418 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/95/04/ff642e65ad6b90db43e668d70ffb6736436c7ce41fcc549f4e9472234127/h11-0.14.0-py3-none-any.whl", hash = "sha256:e3fe4ac4b851c468cc8363d500db52c2ead036020723024a109d37346efaa761", size = 58259 },
            ]

            [[package]]
            name = "httpcore"
            version = "1.0.7"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "certifi" },
                { name = "h11" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/6a/41/d7d0a89eb493922c37d343b607bc1b5da7f5be7e383740b4753ad8943e90/httpcore-1.0.7.tar.gz", hash = "sha256:8551cb62a169ec7162ac7be8d4817d561f60e08eaa485234898414bb5a8a0b4c", size = 85196 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/87/f5/72347bc88306acb359581ac4d52f23c0ef445b57157adedb9aee0cd689d2/httpcore-1.0.7-py3-none-any.whl", hash = "sha256:a3fff8f43dc260d5bd363d9f9cf1830fa3a458b332856f34282de498ed420edd", size = 78551 },
            ]

            [[package]]
            name = "httpx"
            version = "0.28.1"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "anyio" },
                { name = "certifi" },
                { name = "httpcore" },
                { name = "idna" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/b1/df/48c586a5fe32a0f01324ee087459e112ebb7224f646c0b5023f5e79e9956/httpx-0.28.1.tar.gz", hash = "sha256:75e98c5f16b0f35b567856f597f06ff2270a374470a5c2392242528e3e3e42fc", size = 141406 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/2a/39/e50c7c3a983047577ee07d2a9e53faf5a69493943ec3f6a384bdc792deb2/httpx-0.28.1-py3-none-any.whl", hash = "sha256:d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad", size = 73517 },
            ]

            [[package]]
            name = "humanize"
            version = "4.12.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/38/ff/9f38de04e15bd53f5b64d38e6b9f21357d7b3edee7e398d05aaf407dbdfe/humanize-4.12.0.tar.gz", hash = "sha256:87ff7b43591370b12a1d103c9405849d911d4b039ed22d80b718b62c76eec8a3", size = 80785 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/d5/6b/09e54be6cc58913fd991728b9b8f959b58ade87a2a7684318c3e90e5f1dc/humanize-4.12.0-py3-none-any.whl", hash = "sha256:106a7436a2d545d742c147c469716b3a08424aa143a82103630147c489a89f48", size = 127401 },
            ]

            [[package]]
            name = "idna"
            version = "3.10"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/f1/70/7703c29685631f5a7590aa73f1f1d3fa9a380e654b86af429e0934a32f7d/idna-3.10.tar.gz", hash = "sha256:12f65c9b470abda6dc35cf8e63cc574b1c52b11df2c86030af0ac09b01b13ea9", size = 190490 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/76/c6/c88e154df9c4e1a2a66ccf0005a88dfb2650c1dffb6f5ce603dfbd452ce3/idna-3.10-py3-none-any.whl", hash = "sha256:946d195a0d259cbba61165e88e65941f16e9b36ea6ddb97f00452bae8b1287d3", size = 70442 },
            ]

            [[package]]
            name = "iniconfig"
            version = "2.0.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/d7/4b/cbd8e699e64a6f16ca3a8220661b5f83792b3017d0f79807cb8708d33913/iniconfig-2.0.0.tar.gz", hash = "sha256:2d91e135bf72d31a410b17c16da610a82cb55f6b0477d1a902134b24a455b8b3", size = 4646 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/ef/a6/62565a6e1cf69e10f5727360368e451d4b7f58beeac6173dc9db836a5b46/iniconfig-2.0.0-py3-none-any.whl", hash = "sha256:b6a85871a79d2e3b22d2d1b94ac2824226a63c6b741c88f7ae975f18b6778374", size = 5892 },
            ]

            [[package]]
            name = "packaging"
            version = "24.2"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/d0/63/68dbb6eb2de9cb10ee4c9c14a0148804425e13c4fb20d61cce69f53106da/packaging-24.2.tar.gz", hash = "sha256:c228a6dc5e932d346bc5739379109d49e8853dd8223571c7c5b55260edc0b97f", size = 163950 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/88/ef/eb23f262cca3c0c4eb7ab1933c3b1f03d021f2c48f54763065b6f0e321be/packaging-24.2-py3-none-any.whl", hash = "sha256:09abb1bccd265c01f4a3aa3f7a7db064b36514d2cba19a2f694fe6150451a759", size = 65451 },
            ]

            [[package]]
            name = "pluggy"
            version = "1.5.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/96/2d/02d4312c973c6050a18b314a5ad0b3210edb65a906f868e31c111dede4a6/pluggy-1.5.0.tar.gz", hash = "sha256:2cffa88e94fdc978c4c574f15f9e59b7f4201d439195c3715ca9e2486f1d0cf1", size = 67955 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/88/5f/e351af9a41f866ac3f1fac4ca0613908d9a41741cfcf2228f4ad853b697d/pluggy-1.5.0-py3-none-any.whl", hash = "sha256:44e1ad92c8ca002de6377e165f3e0f1be63266ab4d554740532335b9d75ea669", size = 20556 },
            ]

            [[package]]
            name = "pytest"
            version = "8.3.4"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "colorama", marker = "sys_platform == 'win32'" },
                { name = "iniconfig" },
                { name = "packaging" },
                { name = "pluggy" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/05/35/30e0d83068951d90a01852cb1cef56e5d8a09d20c7f511634cc2f7e0372a/pytest-8.3.4.tar.gz", hash = "sha256:965370d062bce11e73868e0335abac31b4d3de0e82f4007408d242b4f8610761", size = 1445919 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/11/92/76a1c94d3afee238333bc0a42b82935dd8f9cf8ce9e336ff87ee14d9e1cf/pytest-8.3.4-py3-none-any.whl", hash = "sha256:50e16d954148559c9a74109af1eaf0c945ba2d8f30f0a3d3335edde19788b6f6", size = 343083 },
            ]

            [[package]]
            name = "pytest-httpx"
            version = "0.35.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "httpx" },
                { name = "pytest" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/1f/89/5b12b7b29e3d0af3a4b9c071ee92fa25a9017453731a38f08ba01c280f4c/pytest_httpx-0.35.0.tar.gz", hash = "sha256:d619ad5d2e67734abfbb224c3d9025d64795d4b8711116b1a13f72a251ae511f", size = 54146 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/b0/ed/026d467c1853dd83102411a78126b4842618e86c895f93528b0528c7a620/pytest_httpx-0.35.0-py3-none-any.whl", hash = "sha256:ee11a00ffcea94a5cbff47af2114d34c5b231c326902458deed73f9c459fd744", size = 19442 },
            ]

            [[package]]
            name = "sniffio"
            version = "1.3.1"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/a2/87/a6771e1546d97e7e041b6ae58d80074f81b7d5121207425c964ddf5cfdbd/sniffio-1.3.1.tar.gz", hash = "sha256:f4324edc670a0f49750a81b895f35c3adb843cca46f0530f79fc1babb23789dc", size = 20372 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/e9/44/75a9c9421471a6c4805dbf2356f7c181a29c1879239abab1ea2cc8f38b40/sniffio-1.3.1-py3-none-any.whl", hash = "sha256:2f6da418d1f1e0fddd844478f41680e794e6051915791a034ff65e5f100525a2", size = 10235 },
            ]

            [[package]]
            name = "test-uv-lock"
            version = "0.1.0"
            source = { virtual = "." }
            dependencies = [
                { name = "httpx" },
                { name = "humanize" },
            ]

            [package.dev-dependencies]
            dev = [
                { name = "pytest-httpx" },
            ]

            [package.metadata]
            requires-dist = [
                { name = "httpx", specifier = ">=0.28.1" },
                { name = "humanize", specifier = ">=4.12.0" },
            ]

            [package.metadata.requires-dev]
            dev = [{ name = "pytest-httpx", specifier = ">=0.35.0" }]
            """,
            [
                Dependency(name="anyio", version="4.8.0", first_order=False),
                Dependency(name="certifi", version="2025.1.31", first_order=False),
                Dependency(name="colorama", version="0.4.6", first_order=False),
                Dependency(name="h11", version="0.14.0", first_order=False),
                Dependency(name="httpcore", version="1.0.7", first_order=False),
                Dependency(name="httpx", version="0.28.1", first_order=True),
                Dependency(name="humanize", version="4.12.0", first_order=True),
                Dependency(name="idna", version="3.10", first_order=False),
                Dependency(name="iniconfig", version="2.0.0", first_order=False),
                Dependency(name="packaging", version="24.2", first_order=False),
                Dependency(name="pluggy", version="1.5.0", first_order=False),
                Dependency(name="pytest", version="8.3.4", first_order=False),
                Dependency(name="pytest-httpx", version="0.35.0", first_order=True),
                Dependency(name="sniffio", version="1.3.1", first_order=False),
            ],
            id="First order and transitive dependencies - app uv.lock file",
        ),
        pytest.param(
            """
            version = 1
            revision = 1
            requires-python = ">=3.13"

            [[package]]
            name = "test-uv-lock-package"
            version = "0.1.0"
            source = { editable = "." }
            """,
            [],
            id="No dependencies - package uv.lock file",
        ),
        pytest.param(
            """
            version = 1
            revision = 1
            requires-python = ">=3.13"

            [[package]]
            name = "humanize"
            version = "4.12.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/38/ff/9f38de04e15bd53f5b64d38e6b9f21357d7b3edee7e398d05aaf407dbdfe/humanize-4.12.0.tar.gz", hash = "sha256:87ff7b43591370b12a1d103c9405849d911d4b039ed22d80b718b62c76eec8a3", size = 80785 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/d5/6b/09e54be6cc58913fd991728b9b8f959b58ade87a2a7684318c3e90e5f1dc/humanize-4.12.0-py3-none-any.whl", hash = "sha256:106a7436a2d545d742c147c469716b3a08424aa143a82103630147c489a89f48", size = 127401 },
            ]

            [[package]]
            name = "test-uv-lock-package"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [
                { name = "humanize" },
            ]

            [package.metadata]
            requires-dist = [{ name = "humanize", specifier = ">=4.12.0" }]
            """,
            [Dependency(name="humanize", version="4.12.0", first_order=True)],
            id="First order dependency - package uv.lock file",
        ),
        pytest.param(
            """
            version = 1
            revision = 1
            requires-python = ">=3.13"

            [[package]]
            name = "anyio"
            version = "4.8.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "idna" },
                { name = "sniffio" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/a3/73/199a98fc2dae33535d6b8e8e6ec01f8c1d76c9adb096c6b7d64823038cde/anyio-4.8.0.tar.gz", hash = "sha256:1d9fe889df5212298c0c0723fa20479d1b94883a2df44bd3897aa91083316f7a", size = 181126 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/46/eb/e7f063ad1fec6b3178a3cd82d1a3c4de82cccf283fc42746168188e1cdd5/anyio-4.8.0-py3-none-any.whl", hash = "sha256:b5011f270ab5eb0abf13385f851315585cc37ef330dd88e27ec3d34d651fd47a", size = 96041 },
            ]

            [[package]]
            name = "certifi"
            version = "2025.1.31"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/1c/ab/c9f1e32b7b1bf505bf26f0ef697775960db7932abeb7b516de930ba2705f/certifi-2025.1.31.tar.gz", hash = "sha256:3d5da6925056f6f18f119200434a4780a94263f10d1c21d032a6f6b2baa20651", size = 167577 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/38/fc/bce832fd4fd99766c04d1ee0eead6b0ec6486fb100ae5e74c1d91292b982/certifi-2025.1.31-py3-none-any.whl", hash = "sha256:ca78db4565a652026a4db2bcdf68f2fb589ea80d0be70e03929ed730746b84fe", size = 166393 },
            ]

            [[package]]
            name = "colorama"
            version = "0.4.6"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/d8/53/6f443c9a4a8358a93a6792e2acffb9d9d5cb0a5cfd8802644b7b1c9a02e4/colorama-0.4.6.tar.gz", hash = "sha256:08695f5cb7ed6e0531a20572697297273c47b8cae5a63ffc6d6ed5c201be6e44", size = 27697 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/d1/d6/3965ed04c63042e047cb6a3e6ed1a63a35087b6a609aa3a15ed8ac56c221/colorama-0.4.6-py2.py3-none-any.whl", hash = "sha256:4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6", size = 25335 },
            ]

            [[package]]
            name = "h11"
            version = "0.14.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/f5/38/3af3d3633a34a3316095b39c8e8fb4853a28a536e55d347bd8d8e9a14b03/h11-0.14.0.tar.gz", hash = "sha256:8f19fbbe99e72420ff35c00b27a34cb9937e902a8b810e2c88300c6f0a3b699d", size = 100418 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/95/04/ff642e65ad6b90db43e668d70ffb6736436c7ce41fcc549f4e9472234127/h11-0.14.0-py3-none-any.whl", hash = "sha256:e3fe4ac4b851c468cc8363d500db52c2ead036020723024a109d37346efaa761", size = 58259 },
            ]

            [[package]]
            name = "httpcore"
            version = "1.0.7"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "certifi" },
                { name = "h11" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/6a/41/d7d0a89eb493922c37d343b607bc1b5da7f5be7e383740b4753ad8943e90/httpcore-1.0.7.tar.gz", hash = "sha256:8551cb62a169ec7162ac7be8d4817d561f60e08eaa485234898414bb5a8a0b4c", size = 85196 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/87/f5/72347bc88306acb359581ac4d52f23c0ef445b57157adedb9aee0cd689d2/httpcore-1.0.7-py3-none-any.whl", hash = "sha256:a3fff8f43dc260d5bd363d9f9cf1830fa3a458b332856f34282de498ed420edd", size = 78551 },
            ]

            [[package]]
            name = "httpx"
            version = "0.28.1"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "anyio" },
                { name = "certifi" },
                { name = "httpcore" },
                { name = "idna" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/b1/df/48c586a5fe32a0f01324ee087459e112ebb7224f646c0b5023f5e79e9956/httpx-0.28.1.tar.gz", hash = "sha256:75e98c5f16b0f35b567856f597f06ff2270a374470a5c2392242528e3e3e42fc", size = 141406 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/2a/39/e50c7c3a983047577ee07d2a9e53faf5a69493943ec3f6a384bdc792deb2/httpx-0.28.1-py3-none-any.whl", hash = "sha256:d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad", size = 73517 },
            ]

            [[package]]
            name = "humanize"
            version = "4.12.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/38/ff/9f38de04e15bd53f5b64d38e6b9f21357d7b3edee7e398d05aaf407dbdfe/humanize-4.12.0.tar.gz", hash = "sha256:87ff7b43591370b12a1d103c9405849d911d4b039ed22d80b718b62c76eec8a3", size = 80785 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/d5/6b/09e54be6cc58913fd991728b9b8f959b58ade87a2a7684318c3e90e5f1dc/humanize-4.12.0-py3-none-any.whl", hash = "sha256:106a7436a2d545d742c147c469716b3a08424aa143a82103630147c489a89f48", size = 127401 },
            ]

            [[package]]
            name = "idna"
            version = "3.10"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/f1/70/7703c29685631f5a7590aa73f1f1d3fa9a380e654b86af429e0934a32f7d/idna-3.10.tar.gz", hash = "sha256:12f65c9b470abda6dc35cf8e63cc574b1c52b11df2c86030af0ac09b01b13ea9", size = 190490 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/76/c6/c88e154df9c4e1a2a66ccf0005a88dfb2650c1dffb6f5ce603dfbd452ce3/idna-3.10-py3-none-any.whl", hash = "sha256:946d195a0d259cbba61165e88e65941f16e9b36ea6ddb97f00452bae8b1287d3", size = 70442 },
            ]

            [[package]]
            name = "iniconfig"
            version = "2.0.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/d7/4b/cbd8e699e64a6f16ca3a8220661b5f83792b3017d0f79807cb8708d33913/iniconfig-2.0.0.tar.gz", hash = "sha256:2d91e135bf72d31a410b17c16da610a82cb55f6b0477d1a902134b24a455b8b3", size = 4646 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/ef/a6/62565a6e1cf69e10f5727360368e451d4b7f58beeac6173dc9db836a5b46/iniconfig-2.0.0-py3-none-any.whl", hash = "sha256:b6a85871a79d2e3b22d2d1b94ac2824226a63c6b741c88f7ae975f18b6778374", size = 5892 },
            ]

            [[package]]
            name = "packaging"
            version = "24.2"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/d0/63/68dbb6eb2de9cb10ee4c9c14a0148804425e13c4fb20d61cce69f53106da/packaging-24.2.tar.gz", hash = "sha256:c228a6dc5e932d346bc5739379109d49e8853dd8223571c7c5b55260edc0b97f", size = 163950 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/88/ef/eb23f262cca3c0c4eb7ab1933c3b1f03d021f2c48f54763065b6f0e321be/packaging-24.2-py3-none-any.whl", hash = "sha256:09abb1bccd265c01f4a3aa3f7a7db064b36514d2cba19a2f694fe6150451a759", size = 65451 },
            ]

            [[package]]
            name = "pluggy"
            version = "1.5.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/96/2d/02d4312c973c6050a18b314a5ad0b3210edb65a906f868e31c111dede4a6/pluggy-1.5.0.tar.gz", hash = "sha256:2cffa88e94fdc978c4c574f15f9e59b7f4201d439195c3715ca9e2486f1d0cf1", size = 67955 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/88/5f/e351af9a41f866ac3f1fac4ca0613908d9a41741cfcf2228f4ad853b697d/pluggy-1.5.0-py3-none-any.whl", hash = "sha256:44e1ad92c8ca002de6377e165f3e0f1be63266ab4d554740532335b9d75ea669", size = 20556 },
            ]

            [[package]]
            name = "pytest"
            version = "8.3.4"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "colorama", marker = "sys_platform == 'win32'" },
                { name = "iniconfig" },
                { name = "packaging" },
                { name = "pluggy" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/05/35/30e0d83068951d90a01852cb1cef56e5d8a09d20c7f511634cc2f7e0372a/pytest-8.3.4.tar.gz", hash = "sha256:965370d062bce11e73868e0335abac31b4d3de0e82f4007408d242b4f8610761", size = 1445919 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/11/92/76a1c94d3afee238333bc0a42b82935dd8f9cf8ce9e336ff87ee14d9e1cf/pytest-8.3.4-py3-none-any.whl", hash = "sha256:50e16d954148559c9a74109af1eaf0c945ba2d8f30f0a3d3335edde19788b6f6", size = 343083 },
            ]

            [[package]]
            name = "pytest-httpx"
            version = "0.35.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "httpx" },
                { name = "pytest" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/1f/89/5b12b7b29e3d0af3a4b9c071ee92fa25a9017453731a38f08ba01c280f4c/pytest_httpx-0.35.0.tar.gz", hash = "sha256:d619ad5d2e67734abfbb224c3d9025d64795d4b8711116b1a13f72a251ae511f", size = 54146 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/b0/ed/026d467c1853dd83102411a78126b4842618e86c895f93528b0528c7a620/pytest_httpx-0.35.0-py3-none-any.whl", hash = "sha256:ee11a00ffcea94a5cbff47af2114d34c5b231c326902458deed73f9c459fd744", size = 19442 },
            ]

            [[package]]
            name = "sniffio"
            version = "1.3.1"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/a2/87/a6771e1546d97e7e041b6ae58d80074f81b7d5121207425c964ddf5cfdbd/sniffio-1.3.1.tar.gz", hash = "sha256:f4324edc670a0f49750a81b895f35c3adb843cca46f0530f79fc1babb23789dc", size = 20372 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/e9/44/75a9c9421471a6c4805dbf2356f7c181a29c1879239abab1ea2cc8f38b40/sniffio-1.3.1-py3-none-any.whl", hash = "sha256:2f6da418d1f1e0fddd844478f41680e794e6051915791a034ff65e5f100525a2", size = 10235 },
            ]

            [[package]]
            name = "test-uv-lock-package"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [
                { name = "httpx" },
                { name = "humanize" },
            ]

            [package.dev-dependencies]
            dev = [
                { name = "pytest-httpx" },
            ]

            [package.metadata]
            requires-dist = [
                { name = "httpx", specifier = ">=0.28.1" },
                { name = "humanize", specifier = ">=4.12.0" },
            ]

            [package.metadata.requires-dev]
            dev = [{ name = "pytest-httpx", specifier = ">=0.35.0" }]
            """,
            [
                Dependency(name="anyio", version="4.8.0", first_order=False),
                Dependency(name="certifi", version="2025.1.31", first_order=False),
                Dependency(name="colorama", version="0.4.6", first_order=False),
                Dependency(name="h11", version="0.14.0", first_order=False),
                Dependency(name="httpcore", version="1.0.7", first_order=False),
                Dependency(name="httpx", version="0.28.1", first_order=True),
                Dependency(name="humanize", version="4.12.0", first_order=True),
                Dependency(name="idna", version="3.10", first_order=False),
                Dependency(name="iniconfig", version="2.0.0", first_order=False),
                Dependency(name="packaging", version="24.2", first_order=False),
                Dependency(name="pluggy", version="1.5.0", first_order=False),
                Dependency(name="pytest", version="8.3.4", first_order=False),
                Dependency(name="pytest-httpx", version="0.35.0", first_order=True),
                Dependency(name="sniffio", version="1.3.1", first_order=False),
            ],
            id="First order and transitive dependencies - package uv.lock file",
        ),
    ],
)
async def test_parse_uv_lock_file(
    tmp_path: Path, uv_lock_contents: str, expected_dependencies: list[Dependency]
) -> None:
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_path.write_text(dedent(uv_lock_contents).strip())
    dependencies = await parse_uv_lock_file(APath(uv_lock_path))
    assert dependencies == expected_dependencies
