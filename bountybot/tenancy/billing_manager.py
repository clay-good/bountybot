"""
Billing Manager

Manages billing and invoicing.
"""

import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from .models import BillingInfo, Invoice, InvoiceStatus


class BillingManager:
    """Manages billing and invoicing."""
    
    def __init__(self):
        """Initialize billing manager."""
        self.billing_info: Dict[str, BillingInfo] = {}  # org_id -> billing_info
        self.invoices: Dict[str, Invoice] = {}
        self.org_invoices: Dict[str, List[str]] = {}  # org_id -> [invoice_ids]
        self.invoice_counter = 1000
    
    def set_billing_info(
        self,
        org_id: str,
        billing_email: str,
        billing_name: str,
        billing_address: str = "",
        billing_city: str = "",
        billing_state: str = "",
        billing_zip: str = "",
        billing_country: str = "",
        payment_method: str = "credit_card",
        tax_id: Optional[str] = None
    ) -> BillingInfo:
        """Set billing information for organization."""
        billing_info = BillingInfo(
            org_id=org_id,
            billing_email=billing_email,
            billing_name=billing_name,
            billing_address=billing_address,
            billing_city=billing_city,
            billing_state=billing_state,
            billing_zip=billing_zip,
            billing_country=billing_country,
            payment_method=payment_method,
            tax_id=tax_id
        )
        
        self.billing_info[org_id] = billing_info
        return billing_info
    
    def get_billing_info(self, org_id: str) -> Optional[BillingInfo]:
        """Get billing information."""
        return self.billing_info.get(org_id)
    
    def create_invoice(
        self,
        org_id: str,
        subscription_id: str,
        line_items: List[Dict],
        due_days: int = 30
    ) -> Invoice:
        """Create an invoice."""
        invoice_id = f"inv_{secrets.token_hex(8)}"
        invoice_number = f"INV-{self.invoice_counter}"
        self.invoice_counter += 1
        
        # Calculate totals
        subtotal = sum(item.get('amount', 0) for item in line_items)
        
        # Calculate tax (simplified - 10% for demo)
        billing_info = self.billing_info.get(org_id)
        tax_rate = 0.0 if (billing_info and billing_info.tax_exempt) else 0.10
        tax = subtotal * tax_rate
        
        total = subtotal + tax
        
        issue_date = datetime.utcnow()
        due_date = issue_date + timedelta(days=due_days)
        
        invoice = Invoice(
            invoice_id=invoice_id,
            org_id=org_id,
            subscription_id=subscription_id,
            invoice_number=invoice_number,
            status=InvoiceStatus.PENDING,
            issue_date=issue_date,
            due_date=due_date,
            subtotal=subtotal,
            tax=tax,
            total=total,
            line_items=line_items
        )
        
        self.invoices[invoice_id] = invoice
        
        if org_id not in self.org_invoices:
            self.org_invoices[org_id] = []
        self.org_invoices[org_id].append(invoice_id)
        
        return invoice
    
    def get_invoice(self, invoice_id: str) -> Optional[Invoice]:
        """Get invoice by ID."""
        return self.invoices.get(invoice_id)
    
    def list_invoices(
        self,
        org_id: str,
        status: Optional[InvoiceStatus] = None,
        limit: int = 100
    ) -> List[Invoice]:
        """List invoices for organization."""
        invoice_ids = self.org_invoices.get(org_id, [])
        invoices = [self.invoices[inv_id] for inv_id in invoice_ids if inv_id in self.invoices]
        
        if status:
            invoices = [inv for inv in invoices if inv.status == status]
        
        # Sort by issue date (newest first)
        invoices.sort(key=lambda x: x.issue_date, reverse=True)
        
        return invoices[:limit]
    
    def mark_invoice_paid(
        self,
        invoice_id: str,
        payment_method: str,
        payment_reference: Optional[str] = None
    ) -> bool:
        """Mark invoice as paid."""
        invoice = self.invoices.get(invoice_id)
        if not invoice:
            return False
        
        invoice.status = InvoiceStatus.PAID
        invoice.paid_date = datetime.utcnow()
        invoice.payment_method = payment_method
        invoice.payment_reference = payment_reference
        
        return True
    
    def mark_invoice_overdue(self, invoice_id: str) -> bool:
        """Mark invoice as overdue."""
        invoice = self.invoices.get(invoice_id)
        if not invoice:
            return False
        
        if invoice.status == InvoiceStatus.PENDING:
            invoice.status = InvoiceStatus.OVERDUE
            return True
        
        return False
    
    def cancel_invoice(self, invoice_id: str) -> bool:
        """Cancel an invoice."""
        invoice = self.invoices.get(invoice_id)
        if not invoice:
            return False
        
        invoice.status = InvoiceStatus.CANCELLED
        return True
    
    def get_billing_summary(self, org_id: str) -> Dict:
        """Get billing summary for organization."""
        invoices = self.list_invoices(org_id)
        
        total_paid = sum(inv.total for inv in invoices if inv.status == InvoiceStatus.PAID)
        total_pending = sum(inv.total for inv in invoices if inv.status == InvoiceStatus.PENDING)
        total_overdue = sum(inv.total for inv in invoices if inv.status == InvoiceStatus.OVERDUE)
        
        return {
            'org_id': org_id,
            'total_invoices': len(invoices),
            'total_paid': total_paid,
            'total_pending': total_pending,
            'total_overdue': total_overdue,
            'has_overdue': total_overdue > 0,
            'recent_invoices': [
                {
                    'invoice_id': inv.invoice_id,
                    'invoice_number': inv.invoice_number,
                    'status': inv.status.value,
                    'total': inv.total,
                    'due_date': inv.due_date.isoformat() if inv.due_date else None
                }
                for inv in invoices[:5]
            ]
        }
    
    def check_overdue_invoices(self):
        """Check and mark overdue invoices."""
        now = datetime.utcnow()
        overdue_count = 0
        
        for invoice in self.invoices.values():
            if invoice.status == InvoiceStatus.PENDING and invoice.due_date:
                if now > invoice.due_date:
                    invoice.status = InvoiceStatus.OVERDUE
                    overdue_count += 1
        
        return overdue_count
    
    def generate_monthly_invoice(
        self,
        org_id: str,
        subscription_id: str,
        plan_name: str,
        plan_price: float,
        usage_charges: Optional[List[Dict]] = None
    ) -> Invoice:
        """Generate monthly invoice for subscription."""
        line_items = [
            {
                'description': f'{plan_name} Plan - Monthly Subscription',
                'quantity': 1,
                'unit_price': plan_price,
                'amount': plan_price
            }
        ]
        
        # Add usage-based charges
        if usage_charges:
            line_items.extend(usage_charges)
        
        return self.create_invoice(org_id, subscription_id, line_items)
    
    def get_payment_history(self, org_id: str, limit: int = 50) -> List[Dict]:
        """Get payment history for organization."""
        invoices = self.list_invoices(org_id, status=InvoiceStatus.PAID, limit=limit)
        
        return [
            {
                'invoice_id': inv.invoice_id,
                'invoice_number': inv.invoice_number,
                'amount': inv.total,
                'currency': inv.currency,
                'paid_date': inv.paid_date.isoformat() if inv.paid_date else None,
                'payment_method': inv.payment_method,
                'payment_reference': inv.payment_reference
            }
            for inv in invoices
        ]

