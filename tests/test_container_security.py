"""Adversarial container regressions for provenance and parser coverage."""

from __future__ import annotations

import base64
import io
import struct
import zipfile
import zlib

import pytest

import hiddenink.core.formats._safety as safety_limits
import hiddenink.core.formats.documents as document_parser
import hiddenink.core.formats.jpeg as jpeg_parser
import hiddenink.core.formats.png as png_parser
from hiddenink.core.formats import detect_format, inspect_file
from hiddenink.core.formats.clean import clean_bytes
from hiddenink.core.formats.documents import parse_office, parse_pdf, parse_svg
from hiddenink.core.formats.jpeg import parse_jpeg, scan_jpeg
from hiddenink.core.formats.png import PNG_SIGNATURE, parse_png, scan_png
from hiddenink.core.formats.provenance import (
    C2PA_MANIFEST_UUID,
    inspect_jumbf_manifest_store,
)
from test_formats import (
    _box,
    _jpeg_segment,
    _png_chunk,
    build_jpeg,
    build_manifest_store,
    build_png,
)


class TestProvenanceStates:
    def test_jumbf_structure_is_not_credential_verification(self) -> None:
        status = inspect_jumbf_manifest_store(build_manifest_store())
        assert status.looks_like_jumbf
        assert status.manifest_store_parsed

        found = parse_png(build_png(c2pa=True))
        assert found["png.c2pa_like"]
        assert found["png.c2pa_manifest_store_structurally_parsed"] is True
        assert found["png.c2pa_credential_verified"].startswith("unavailable")

    def test_cbor_child_is_not_a_structurally_parsed_manifest_store(self) -> None:
        description = _box(
            b"jumd", C2PA_MANIFEST_UUID + b"\x03c2pa\x00"
        )
        fake_store = _box(b"jumb", description + _box(b"cbor", b"\xa0"))

        status = inspect_jumbf_manifest_store(fake_store)

        assert status.looks_like_jumbf
        assert not status.manifest_store_parsed
        assert "no C2PA Manifest superbox" in status.reason

    def test_manifest_superbox_requires_a_urn_c2pa_label(self) -> None:
        store_description = _box(
            b"jumd", C2PA_MANIFEST_UUID + b"\x03c2pa\x00"
        )
        manifest_description = _box(
            b"jumd",
            bytes.fromhex("63326d6100110010800000aa00389b71")
            + b"\x03not-a-c2pa-urn\x00",
        )
        fake_manifest = _box(
            b"jumb", manifest_description + _box(b"cbor", b"\xa0")
        )

        status = inspect_jumbf_manifest_store(
            _box(b"jumb", store_description + fake_manifest)
        )

        assert not status.manifest_store_parsed

    def test_legacy_c2md_manifest_superbox_is_structurally_recognised(self) -> None:
        store_description = _box(
            b"jumd", C2PA_MANIFEST_UUID + b"\x03c2pa\x00"
        )
        manifest_description = _box(
            b"jumd",
            bytes.fromhex("63326d6400110010800000aa00389b71")
            + b"\x03urn:c2pa:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4\x00",
        )
        manifest = _box(b"jumb", manifest_description + _box(b"cbor", b"\xa0"))

        status = inspect_jumbf_manifest_store(
            _box(b"jumb", store_description + manifest)
        )

        assert status.manifest_store_parsed

    def test_arbitrary_cabx_payload_is_only_c2pa_like_and_blocks_mutation(self) -> None:
        plain = build_png(text={"Author": "person"})
        cabx = _png_chunk(b"caBX", b"this is not JUMBF")
        data = plain.replace(
            _png_chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff")),
            cabx + _png_chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff")),
        )
        found = parse_png(data)
        assert "png.c2pa_like" in found
        assert "png.c2pa_manifest_store_structurally_parsed" not in found

        cleaned, report = clean_bytes(data, "png")
        assert cleaned == data
        assert report.parse_status == "refused"
        assert "png.refusal.provenance" in report.metadata

    def test_jpeg_xt_jumbf_like_but_malformed_refuses_cleaning(self) -> None:
        malformed_jumbf = struct.pack(">I4s", 100, b"jumb") + b"short"
        app11 = _jpeg_segment(0xEB, b"JP\x00\x01\x00\x00\x00\x01" + malformed_jumbf)
        data = build_jpeg().replace(b"\xff\xfe", app11 + b"\xff\xfe", 1)
        found = parse_jpeg(data)
        assert "jpeg.c2pa_like" in found
        assert "jpeg.c2pa_manifest_store_structurally_parsed" not in found
        cleaned, report = clean_bytes(data, "jpeg")
        assert cleaned == data
        assert report.parse_status == "refused"

    def test_svg_requires_exact_manifest_element_and_structural_payload(self) -> None:
        encoded = base64.b64encode(build_manifest_store()).decode("ascii")
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" '
            'xmlns:c2pa="http://c2pa.org/manifest"><metadata>'
            f"<c2pa:manifest>{encoded}</c2pa:manifest>"
            "</metadata></svg>"
        ).encode()
        found = parse_svg(svg)
        assert found["svg.c2pa_manifest_store_structurally_parsed"] is True
        assert found["svg.c2pa_credential_verified"].startswith("unavailable")

    def test_arbitrary_c2pa_filename_in_office_is_not_a_manifest(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("media/my-c2pa-notes.txt", "c2pa")
        found = parse_office(stream.getvalue())
        assert not any("c2pa" in key for key in found)


class TestPngStructuralRefusal:
    @pytest.mark.parametrize(
        "mutator",
        [
            lambda data: data[:-12],
            lambda data: data + b"trailer",
            lambda data: data[:29] + bytes([data[29] ^ 1]) + data[30:],
        ],
    )
    def test_malformed_png_round_trips_byte_identical(self, mutator) -> None:
        original = mutator(build_png(text={"Author": "person"}))
        cleaned, report = clean_bytes(original, "png")
        assert cleaned == original
        assert report.parse_status == "refused"
        assert report.refusal_reasons

    def test_required_idat_and_ordering_are_checked(self) -> None:
        header = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        no_idat = PNG_SIGNATURE + header + _png_chunk(b"IEND", b"")
        assert scan_png(no_idat).status == "malformed"

        split_idat = (
            PNG_SIGNATURE
            + header
            + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
            + _png_chunk(b"tEXt", b"Title\x00x")
            + _png_chunk(b"IDAT", b"")
            + _png_chunk(b"IEND", b"")
        )
        assert "not consecutive" in scan_png(split_idat).reason

    def test_chunk_count_limit_is_cumulative(self, monkeypatch) -> None:
        monkeypatch.setattr(png_parser, "MAX_CONTAINER_ITEMS", 3)
        data = build_png(text={"one": "1", "two": "2"})
        found = parse_png(data)
        assert found["png.parse_status"] == "resource_limit"
        assert "chunk-count limit" in found["png.warning.structure"]

    def test_metadata_byte_limit_is_cumulative(self, monkeypatch) -> None:
        monkeypatch.setattr(png_parser, "MAX_METADATA_BYTES", 10)
        found = parse_png(build_png(text={"one": "1234", "two": "5678"}))
        assert found["png.parse_status"] == "resource_limit"
        assert "png.warning.metadata_limit" in found


class TestJpegStructuralRefusal:
    def test_missing_frame_is_malformed_even_with_sos_and_eoi(self) -> None:
        data = b"\xff\xd8" + _jpeg_segment(0xFE, b"privacy")
        data += b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\xff\xd9"
        assert scan_jpeg(data).status == "malformed"
        cleaned, report = clean_bytes(data, "jpeg")
        assert cleaned == data
        assert report.parse_status == "refused"

    def test_invalid_segment_length_is_malformed(self) -> None:
        data = b"\xff\xd8\xff\xe1\x00\x01\xff\xd9"
        scan = scan_jpeg(data)
        assert scan.status == "malformed"
        assert "smaller" in scan.reason

    def test_c2pa_second_pass_stops_at_aggregate_metadata_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app11_body = b"JP\x00\x01\x00\x00\x00\x01" + b"12345678"
        separated_runs = (
            _jpeg_segment(0xEB, app11_body)
            + _jpeg_segment(0xE0, b"separator")
            + _jpeg_segment(0xEB, app11_body)
        )
        data = build_jpeg().replace(b"\xff\xfe", separated_runs + b"\xff\xfe", 1)
        monkeypatch.setattr(jpeg_parser, "MAX_METADATA_BYTES", 24)

        def unexpected_c2pa_parse(_payload: bytes):
            raise AssertionError("C2PA parsing continued past the aggregate limit")

        monkeypatch.setattr(
            jpeg_parser, "inspect_jumbf_manifest_store", unexpected_c2pa_parse
        )

        found = parse_jpeg(data)

        assert found["jpeg.parse_status"] == "resource_limit"
        assert "jpeg.warning.metadata_limit" in found


class TestCoverageAndLimits:
    def test_utf16_svg_is_detected_and_inspected(self, tmp_path) -> None:
        data = "<?xml version='1.0'?><svg><title>Chart</title></svg>".encode("utf-16")
        assert detect_format(data) == "svg"
        path = tmp_path / "chart.bin"
        path.write_bytes(data)
        report = inspect_file(path)
        assert report.parse_status == "complete"
        assert report.metadata["svg.title"] == "Chart"

    def test_pdf_omission_is_never_reported_as_complete(self) -> None:
        validish = b"%PDF-1.7\n1 0 obj << /Title (x) >> endobj\n%%EOF\n"
        found = parse_pdf(validish)
        assert found["pdf.parse_status"] == "partial"
        assert "object streams" in found["pdf.coverage"]

        malformed = parse_pdf(validish.replace(b"%%EOF", b""))
        assert malformed["pdf.parse_status"] == "malformed"

    def test_office_member_count_limit_is_cumulative(self, monkeypatch) -> None:
        monkeypatch.setattr(document_parser, "MAX_CONTAINER_ITEMS", 2)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("docProps/core.xml", "<a/>")
            archive.writestr("word/document.xml", "<document/>")
        found = parse_office(stream.getvalue())
        assert found["office.parse_status"] == "resource_limit"
        assert "office.warning.member_limit" in found

    def test_office_member_limit_is_checked_before_zipfile_allocation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("one", "1")
            archive.writestr("two", "2")
        monkeypatch.setattr(document_parser, "MAX_CONTAINER_ITEMS", 2)

        def unexpected_zipfile(*_args, **_kwargs):
            raise AssertionError("ZipFile allocated before member-count refusal")

        monkeypatch.setattr(document_parser.zipfile, "ZipFile", unexpected_zipfile)

        found = parse_office(stream.getvalue())

        assert found["office.parse_status"] == "resource_limit"

    def test_zip64_member_limit_is_checked_before_zipfile_allocation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        count = document_parser.MAX_CONTAINER_ITEMS + 1
        zip64_eocd = (
            b"PK\x06\x06"
            + struct.pack("<QHHIIQQQQ", 44, 45, 45, 0, 0, count, count, 0, 0)
        )
        locator = b"PK\x06\x07" + struct.pack("<IQI", 0, 0, 1)
        eocd = b"PK\x05\x06" + struct.pack(
            "<4H2IH", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0
        )

        def unexpected_zipfile(*_args, **_kwargs):
            raise AssertionError("ZipFile allocated before ZIP64 count refusal")

        monkeypatch.setattr(document_parser.zipfile, "ZipFile", unexpected_zipfile)

        found = parse_office(zip64_eocd + locator + eocd)

        assert found["office.parse_status"] == "resource_limit"

    def test_xml_size_ceiling_is_reported_as_resource_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(safety_limits, "MAX_XML_BYTES", 32)
        found = parse_svg(b"<svg><title>" + b"x" * 40 + b"</title></svg>")

        assert found["svg.parse_status"] == "resource_limit"
        assert "svg.refusal.xml" not in found

    def test_office_xml_ceiling_is_not_an_entity_policy_refusal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(safety_limits, "MAX_XML_BYTES", 32)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr(
                "docProps/core.xml", b"<a><title>" + b"x" * 40 + b"</title></a>"
            )

        found = parse_office(stream.getvalue())

        assert found["office.parse_status"] == "resource_limit"
        assert "office.refusal.core.xml" not in found

    def test_image_coverage_names_selected_metadata_scope(self) -> None:
        png = parse_png(build_png())
        jpeg = parse_jpeg(build_jpeg())

        assert "selected" in png["png.coverage"]
        assert "selected" in jpeg["jpeg.coverage"]
        assert "complete chunk framing and metadata" not in png["png.coverage"]
        assert "complete marker framing and metadata" not in jpeg["jpeg.coverage"]

    def test_office_xml_entity_causes_security_refusal(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr(
                "docProps/core.xml",
                "<!DOCTYPE a [<!ENTITY x 'expanded'>]><a><title>&x;</title></a>",
            )
        found = parse_office(stream.getvalue())
        assert found["office.parse_status"] == "refused"
        assert "office.refusal.core.xml" in found
