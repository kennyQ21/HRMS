import asyncio
from services.pipeline_manager import PipelineManager
from schemas import PipelineConfig

async def main():
    manager = PipelineManager(PipelineConfig(
        use_gliner=True,
        use_llm=True,
        llm_provider="openai"
    ))
    res = await manager.process_file("sample/1560025797-1707.jpg")
    for pii in res.pii_detected:
        print(f"[{pii.pii_type}] {pii.value} (from {pii.source})")

if __name__ == "__main__":
    asyncio.run(main())
