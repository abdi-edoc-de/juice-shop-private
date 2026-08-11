describe('challenge \"passwordHashLeakChallenge\"', () => {
  beforeEach(() => {
    cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
  })

  it('should NOT leak password hash via fields parameter due to whitelist', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=id,email,password',
      headers: {
        // Cypress automatically handles cookies after cy.login
      }
    }).then((res) => {
      expect(res.body.user.password).to.be.undefined
      expect(res.body.user.id).to.be.a('number')
      expect(res.body.user.email).to.be.a('string')
    })
  })
})
