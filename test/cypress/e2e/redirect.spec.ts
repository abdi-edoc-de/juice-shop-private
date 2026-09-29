describe('/redirect', () => {
  describe('redirect target validation', () => {
    it('should show error page when supplying an unrecognized target URL', () => {
      cy.visit('/redirect?to=http://kimminich.de', {
        failOnStatusCode: false
      })
      cy.contains('Unrecognized target URL for redirect: http://kimminich.de')
    })

    it('should show error page when an allowlisted URL is only contained in the target URL as parameter', () => {
      cy.visit(
        '/redirect?to=https://owasp.org?trickIndexOf=https://github.com/juice-shop/juice-shop',
        {
          failOnStatusCode: false
        }
      )
      cy.contains('Unrecognized target URL for redirect')
    })
  })

  describe('challenge "redirectCryptoCurrencyChallenge"', () => {
    it('should still redirect to forgotten entry https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6 on allowlist', () => {
      cy.visit(
        '/redirect?to=https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6',
        {
          failOnStatusCode: false
        }
      )
      cy.expectChallengeSolved({ challenge: 'Outdated Allowlist' })
    })
  })
})
