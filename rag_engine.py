"""
RAG ENGINE - Fraud Intelligence Analysis
Retrieves fraud patterns from CyborgDB and generates insights using Gemini
"""

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableSequence

from database import CyborgDB
from typing import List, Dict
import os


class FraudRAGEngine:
    """RAG system for fraud pattern analysis"""

    def __init__(self):
        """Initialize RAG engine with Gemini"""

        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("GOOGLE_API_KEY not set in environment")

        # Initialize Gemini
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            google_api_key=api_key,
            temperature=0.3
        )

        # Initialize CyborgDB
        self.db = CyborgDB()

        print("✅ RAG Engine initialized with Gemini 2.5 Flash")

    # ------------------------------------------------------------------
    # RETRIEVAL
    # ------------------------------------------------------------------

    def retrieve_context(
        self,
        query: str,
        bank_filter: str = "All",
        top_k: int = 10
    ) -> List[Dict]:
        """Retrieve relevant transactions from CyborgDB"""

        results = self.db.secure_search(
            query_text=query,
            bank_filter=bank_filter,
            min_amount=0,
            user_id_filter="admin"
        )

        return results[:top_k]

    # ------------------------------------------------------------------
    # MAIN RAG PIPELINE
    # ------------------------------------------------------------------

    def generate_fraud_report(
        self,
        query: str,
        bank_filter: str = "All"
    ) -> Dict:
        """Generate comprehensive fraud analysis report using RAG"""

        print(f"🔍 Retrieving fraud patterns for: '{query}'")
        retrieved_docs = self.retrieve_context(query, bank_filter)

        if not retrieved_docs:
            return {
                "query": query,
                "analysis": "No matching fraud patterns found in the database.",
                "retrieved_count": 0,
                "transactions": []
            }

        context = self._format_context(retrieved_docs)

        print("🤖 Generating fraud intelligence report...")
        analysis = self._generate_analysis(query, context, bank_filter)

        return {
            "query": query,
            "analysis": analysis,
            "retrieved_count": len(retrieved_docs),
            "transactions": retrieved_docs
        }

    # ------------------------------------------------------------------
    # CONTEXT FORMATTING
    # ------------------------------------------------------------------

    def _format_context(self, results: List[Dict]) -> str:
        """Format retrieved transactions for LLM context"""

        context_parts = []

        for i, res in enumerate(results, 1):
            meta = res.get("metadata", {})
            context_parts.append(
                f"Transaction {i}:\n"
                f"- Description: {meta.get('description', 'N/A')}\n"
                f"- Amount: ${meta.get('amount', 0):.2f}\n"
                f"- Bank: {meta.get('bank', 'N/A')}\n"
                f"- Risk Level: {res.get('risk_level', 'N/A')}\n"
                f"- Index Source: {res.get('index_source', 'N/A')}\n"
            )

        return "\n".join(context_parts)

    # ------------------------------------------------------------------
    # ANALYSIS (Runnable-based)
    # ------------------------------------------------------------------

    def _generate_analysis(self, query: str, context: str, bank_filter: str) -> str:
        prompt = PromptTemplate(
            input_variables=["query", "context", "bank"],
            template="""You are a fraud detection analyst examining transaction patterns.
    Search Query: {query}
    Bank Filter: {bank}

    Retrieved Transactions:
    {context}

    Provide a concise fraud intelligence report."""
        )

        chain = prompt | self.llm

        try:
            response = chain.invoke({
                "query": query,
                "context": context,
                "bank": bank_filter
            })
            return response.content if isinstance(response.content, str) else str(response)

        except Exception as e:
            return f"Error generating analysis: {str(e)}"



    # ------------------------------------------------------------------
    # QUICK SINGLE-TRANSACTION ANALYSIS
    # ------------------------------------------------------------------

    def quick_threat_analysis(
        self,
        transaction_description: str,
        amount: float,
        bank: str
    ) -> str:
        """Quick threat assessment for a single transaction"""

        try:
            # Retrieve similar patterns
            similar = self.db.secure_search(
                query_text=transaction_description,
                bank_filter=bank,
                min_amount=0,
                user_id_filter="admin"
            )[:5]

            context = (
                self._format_context(similar)
                if similar
                else "No similar patterns found."
            )

            prompt = PromptTemplate(
                input_variables=["description", "amount", "bank", "context"],
                template="""
    Analyze this transaction for fraud risk:

    Transaction Details:
    - Description: {description}
    - Amount: ${amount}
    - Bank: {bank}

    Similar Historical Patterns:
    {context}

    Provide a brief threat assessment:
    - Is this transaction suspicious?
    - What are the risk factors?
    - Should it be approved, flagged, or blocked?
    """
            )

            # Runnable chain (modern LangChain)
            chain = prompt | self.llm

            response = chain.invoke({
                "description": transaction_description,
                "amount": amount,
                "bank": bank,
                "context": context
            })

            # SAFE return for FastAPI
            return (
                response.content
                if isinstance(response.content, str)
                else str(response)
            )

        except Exception as e:
            # Never crash the API
            return f"Threat analysis failed: {str(e)}"



# ------------------------------------------------------------------
# SINGLETON ACCESSOR
# ------------------------------------------------------------------

_rag_engine = None


def get_rag_engine() -> FraudRAGEngine:
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = FraudRAGEngine()
    return _rag_engine

