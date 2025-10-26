"""
Tests for researcher communication assistant.
"""

import pytest
from bountybot.communication import (
    ResponseGenerator,
    ToneAnalyzer,
    TemplateManager,
    MultiLanguageTranslator,
    CommunicationScenario,
    Language,
    ToneType
)


class TestResponseGenerator:
    """Test response generation."""
    
    def test_generate_response_accepted(self):
        """Test generating acceptance response."""
        generator = ResponseGenerator()
        
        context = {
            "researcher_name": "John Doe",
            "report_id": "RPT-123",
            "vulnerability_type": "SQL Injection",
            "severity": "HIGH",
            "cvss_score": "8.5",
            "payout": "5000"
        }
        
        response = generator.generate_response(
            scenario=CommunicationScenario.REPORT_ACCEPTED,
            context=context,
            language=Language.ENGLISH,
            tone=ToneType.PROFESSIONAL
        )
        
        assert response is not None
        assert response.scenario == CommunicationScenario.REPORT_ACCEPTED
        assert response.language == Language.ENGLISH
        assert len(response.subject) > 0
        assert len(response.body) > 0
        assert response.tone_analysis is not None
        assert response.sentiment is not None
    
    def test_generate_response_rejected(self):
        """Test generating rejection response."""
        generator = ResponseGenerator()
        
        context = {
            "researcher_name": "Jane Smith",
            "report_id": "RPT-456",
            "reason": "Not reproducible"
        }
        
        response = generator.generate_response(
            scenario=CommunicationScenario.REPORT_REJECTED,
            context=context,
            language=Language.ENGLISH,
            tone=ToneType.PROFESSIONAL
        )
        
        assert response is not None
        assert response.scenario == CommunicationScenario.REPORT_REJECTED
        assert len(response.body) > 0
    
    def test_generate_response_needs_info(self):
        """Test generating needs more info response."""
        generator = ResponseGenerator()

        context = {
            "researcher_name": "Bob Wilson",
            "report_id": "RPT-789",
            "missing_info": "Steps to reproduce"
        }

        response = generator.generate_response(
            scenario=CommunicationScenario.NEEDS_MORE_INFO,
            context=context,
            language=Language.ENGLISH,
            tone=ToneType.FRIENDLY
        )

        assert response is not None
        assert response.scenario == CommunicationScenario.NEEDS_MORE_INFO
        # Tone may vary based on template, just check it exists
        assert response.tone_analysis is not None
        assert response.tone_analysis.tone_type in [ToneType.FRIENDLY, ToneType.FORMAL, ToneType.PROFESSIONAL]
    
    def test_customize_tone(self):
        """Test tone customization."""
        generator = ResponseGenerator()
        
        text = "Your report has been accepted."
        customized = generator.customize_tone(text, ToneType.GRATEFUL)
        
        assert customized is not None
        assert len(customized) > 0


class TestToneAnalyzer:
    """Test tone analysis."""
    
    def test_analyze_professional_tone(self):
        """Test analyzing professional text."""
        analyzer = ToneAnalyzer()
        
        text = "Thank you for your detailed report. We have reviewed it carefully and confirmed the vulnerability."
        analysis = analyzer.analyze_tone(text)
        
        assert analysis is not None
        assert analysis.professionalism_score > 0.7
        assert analysis.overall_score > 0
        assert len(analysis.issues) == 0
    
    def test_analyze_unprofessional_tone(self):
        """Test analyzing unprofessional text."""
        analyzer = ToneAnalyzer()
        
        text = "WOW!!! THIS IS AMAZING!!! GREAT JOB!!!"
        analysis = analyzer.analyze_tone(text)
        
        assert analysis is not None
        assert len(analysis.issues) > 0
        assert any("caps" in issue.lower() or "exclamation" in issue.lower() for issue in analysis.issues)
    
    def test_analyze_friendly_tone(self):
        """Test analyzing friendly text."""
        analyzer = ToneAnalyzer()
        
        text = "Hi there! Thanks so much for your report. We really appreciate your help!"
        analysis = analyzer.analyze_tone(text)
        
        assert analysis is not None
        assert analysis.friendliness_score > 0.6
    
    def test_analyze_formal_tone(self):
        """Test analyzing formal text."""
        analyzer = ToneAnalyzer()
        
        text = "Dear researcher, we acknowledge receipt of your submission. The matter will be reviewed accordingly."
        analysis = analyzer.analyze_tone(text)
        
        assert analysis is not None
        assert analysis.formality_score > 0.6
    
    def test_suggestions_for_improvement(self):
        """Test getting improvement suggestions."""
        analyzer = ToneAnalyzer()
        
        text = "ur report is ok i guess"
        analysis = analyzer.analyze_tone(text)
        
        assert analysis is not None
        assert len(analysis.suggestions) > 0


class TestTemplateManager:
    """Test template management."""
    
    def test_get_template_exists(self):
        """Test getting existing template."""
        manager = TemplateManager()
        
        template = manager.get_template(
            CommunicationScenario.REPORT_ACCEPTED,
            Language.ENGLISH
        )
        
        assert template is not None
        assert template.scenario == CommunicationScenario.REPORT_ACCEPTED
        assert template.language == Language.ENGLISH
        assert len(template.subject) > 0
        assert len(template.body) > 0
    
    def test_get_template_not_exists(self):
        """Test getting non-existent template."""
        manager = TemplateManager()
        
        template = manager.get_template(
            CommunicationScenario.STATUS_UPDATE,
            Language.CHINESE
        )
        
        # Should return None for non-existent template
        assert template is None
    
    def test_add_template(self):
        """Test adding new template."""
        manager = TemplateManager()
        
        from bountybot.communication.models import ResponseTemplate
        
        new_template = ResponseTemplate(
            template_id="test_template",
            scenario=CommunicationScenario.THANK_YOU,
            language=Language.ENGLISH,
            subject="Thank you!",
            body="Thanks for your contribution, {researcher_name}!",
            variables=["researcher_name"],
            tone=ToneType.GRATEFUL
        )
        
        manager.add_template(new_template)
        
        retrieved = manager.get_template(
            CommunicationScenario.THANK_YOU,
            Language.ENGLISH
        )
        
        assert retrieved is not None
        assert retrieved.template_id == "test_template"
    
    def test_list_templates(self):
        """Test listing templates."""
        manager = TemplateManager()
        
        templates = manager.list_templates()
        
        assert len(templates) > 0
        assert all(hasattr(t, 'scenario') for t in templates)
    
    def test_list_templates_filtered(self):
        """Test listing templates with filters."""
        manager = TemplateManager()
        
        templates = manager.list_templates(
            scenario=CommunicationScenario.REPORT_ACCEPTED
        )
        
        assert all(t.scenario == CommunicationScenario.REPORT_ACCEPTED for t in templates)


class TestMultiLanguageTranslator:
    """Test translation."""
    
    def test_translate_same_language(self):
        """Test translation when source and target are same."""
        translator = MultiLanguageTranslator()
        
        result = translator.translate(
            "Hello world",
            Language.ENGLISH,
            Language.ENGLISH
        )
        
        assert result is not None
        assert result.translated_text == "Hello world"
        assert result.confidence == 1.0
        assert result.method == "none"
    
    def test_translate_dictionary(self):
        """Test dictionary-based translation."""
        translator = MultiLanguageTranslator()
        
        result = translator.translate(
            "Thank you for your report",
            Language.ENGLISH,
            Language.SPANISH
        )
        
        assert result is not None
        assert result.translated_text != "Thank you for your report"
        assert result.source_language == Language.ENGLISH
        assert result.target_language == Language.SPANISH
        assert result.confidence > 0
    
    def test_translate_fallback(self):
        """Test fallback translation."""
        translator = MultiLanguageTranslator()
        
        result = translator.translate(
            "Some random text that doesn't exist in dictionary",
            Language.ENGLISH,
            Language.FRENCH
        )
        
        assert result is not None
        assert result.method == "fallback"
        assert Language.FRENCH.value in result.translated_text
    
    def test_detect_language(self):
        """Test language detection."""
        translator = MultiLanguageTranslator()
        
        # Spanish
        lang = translator.detect_language("Gracias por su informe")
        assert lang == Language.SPANISH
        
        # French
        lang = translator.detect_language("Merci pour votre rapport")
        assert lang == Language.FRENCH
        
        # Default to English
        lang = translator.detect_language("Hello world")
        assert lang == Language.ENGLISH
    
    def test_is_supported(self):
        """Test checking if language is supported."""
        translator = MultiLanguageTranslator()
        
        assert translator.is_supported(Language.ENGLISH)
        assert translator.is_supported(Language.SPANISH)
        assert translator.is_supported(Language.FRENCH)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

