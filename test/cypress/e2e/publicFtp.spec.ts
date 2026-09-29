describe('/ftp', () => {
  describe('challenge "directoryListingChallenge"', () => {
    it('should be able to access file /ftp/acquisitions.md', () => {
      cy.request('/ftp/acquisitions.md')
      cy.expectChallengeSolved({ challenge: 'Confidential Document' })
    })
  })

  describe('challenge "errorHandling"', () => {
    it('should leak information through error message accessing /ftp/easter.egg due to wrong file suffix', () => {
      cy.visit('/ftp/easter.egg', { failOnStatusCode: false })

      cy.get('#stacktrace').then((elements) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(!!elements.length).to.be.true
      })
      cy.expectChallengeSolved({ challenge: 'Error Handling' })
    })
  })

  describe('poison null byte protection', () => {
    const files = [
      '/ftp/coupons_2013.md.bak%2500.md',
      '/ftp/package.json.bak%2500.md',
      '/ftp/eastere.gg%2500.md',
      '/ftp/suspicious_errors.yml%2500.md',
      '/ftp/encrypt.pyc%2500.md'
    ]

    files.forEach((url) => {
      it(`should not serve ${url} despite the appended allowlisted file type`, () => {
        cy.request({ url, failOnStatusCode: false }).then((response) => {
          expect(response.status).to.equal(403)
        })
      })
    })
  })
})
