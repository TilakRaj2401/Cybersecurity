"""Compatibility wrapper exposing the ONNX exporter at the project root."""

from Backend.onnx_exporter import LightweightIoTModel, export_to_onnx

__all__ = ["LightweightIoTModel", "export_to_onnx"]
